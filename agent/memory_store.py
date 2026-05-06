"""
Persistent storage for LangGraph — SQLite-backed conversation checkpoints
plus an in-memory key-value store for the agent's `/memories/` namespace.

Why SQLite (not MemorySaver):
- The UI keeps the latest few chats in the sidebar. Each chat has its own
  thread_id. With MemorySaver, switching chats showed the saved messages
  in the UI but the LangGraph runtime had no checkpoint for the thread, so
  the model lost all prior context and answered as if from scratch.
- AsyncSqliteSaver persists checkpoints to disk keyed by thread_id, so
  reopening a saved chat restores the agent's actual conversation memory.

Why async: the agent is driven by `astream`/`ainvoke`, and the sync
SqliteSaver raises NotImplementedError on the async checkpoint methods
LangGraph calls during streaming.

Why this does not bloat the LLM context:
- The model only ever sees the current thread's checkpoint. Other threads
  in the DB are untouched. Within a single thread, the existing
  summarization middleware in `agent.py` keeps message history bounded.
- We additionally call `prune_threads(...)` from the UI whenever the
  history list changes, so DB rows for evicted chats are deleted.
"""

import asyncio
import logging
import sqlite3

import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.store.memory import InMemoryStore

from config.settings import CHECKPOINT_DB_FILE

logger = logging.getLogger("forensics_agent")

# Module-level cache so every caller shares one checkpointer + connection.
# Keyed implicitly by the running event loop: AsyncSqliteSaver creates an
# asyncio.Lock bound to the loop that was running at construction time, and
# its underlying aiosqlite worker thread is also tied to that loop. If the
# loop changes (Streamlit script reruns can spin up a new per-session loop,
# or hot-reload swaps the loop entirely) we MUST rebuild — reusing the old
# saver raises "Lock is bound to a different event loop".
_checkpointer = None
_checkpointer_loop = None
_store = None


async def _configure_async_pragmas(conn: aiosqlite.Connection) -> None:
    """Set PRAGMAs on the async connection so concurrent readers don't fail.

    `AsyncSqliteSaver.setup()` already enables WAL on first use, but it does
    NOT set a `busy_timeout`. Without one, any sync writer (our prune path,
    or another process opening the same file) racing the saver's first write
    will get an immediate `OperationalError: database is locked` instead of
    waiting. We pre-set both pragmas so the saver's setup is idempotent.
    """
    try:
        try:
            await conn  # awaiting the Connection completes its handshake
        except RuntimeError as err:
            if "threads can only be started once" not in str(err):
                raise
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA busy_timeout=5000")
        await conn.commit()
    except Exception as err:
        logger.warning("Could not pre-configure async sqlite pragmas: %s", err)


async def _close_async_conn_safely(conn: aiosqlite.Connection) -> None:
    """Best-effort close of a connection on its own loop. Swallows errors."""
    try:
        await conn.close()
    except Exception as err:
        logger.debug("Old aiosqlite connection close failed (expected): %s", err)


def get_checkpointer():
    """Return the shared SQLite-backed checkpointer (created on first use).

    Must be called from within a running asyncio event loop. If the running
    loop differs from the one the cached saver was built on, the saver is
    discarded and rebuilt — its asyncio primitives can only be awaited from
    their original loop.
    """
    global _checkpointer, _checkpointer_loop

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if (
        _checkpointer is not None
        and loop is not None
        and _checkpointer_loop is not loop
    ):
        # Loop changed under us — drop the stale saver. Try to close the old
        # connection on its original loop (if still alive) so its sqlite
        # handle and WAL files are released; on Windows leaving the handle
        # to GC can hold a lock and break the next sync prune.
        logger.info("Event loop changed; rebuilding AsyncSqliteSaver.")
        old_loop = _checkpointer_loop
        old_conn = getattr(_checkpointer, "conn", None)
        if old_loop is not None and old_conn is not None and not old_loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    _close_async_conn_safely(old_conn), old_loop
                )
            except Exception as err:
                logger.debug("Could not schedule old conn close: %s", err)
        _checkpointer = None
        _checkpointer_loop = None

    if _checkpointer is None:
        CHECKPOINT_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        # aiosqlite.connect(...) returns a Connection that auto-connects on
        # first await; AsyncSqliteSaver triggers that via _ensure_connected.
        conn = aiosqlite.connect(str(CHECKPOINT_DB_FILE))
        _checkpointer = AsyncSqliteSaver(conn)
        _checkpointer_loop = loop
        # Schedule pragma configuration on the running loop. We don't await
        # here (this function is sync) — the task runs to completion before
        # the caller's first checkpoint write because asyncio is cooperative
        # and our caller will yield via `await create_forensics_agent(...)`.
        if loop is not None:
            loop.create_task(_configure_async_pragmas(conn))
    return _checkpointer


def get_store():
    """Return the shared in-memory key-value store for `/memories/`."""
    global _store
    if _store is None:
        _store = InMemoryStore()
    return _store


def prune_threads(keep_thread_ids):
    """Delete checkpoint data for any thread not in `keep_thread_ids`.

    Uses a synchronous sqlite3 connection on the same DB file because this is
    called from Streamlit's sync code path. AsyncSqliteSaver writes with
    journal_mode=WAL, so a brief sync read/delete here is safe alongside the
    agent's async writes.

    Returns the number of threads deleted. Safe to call before the
    checkpointer has any rows — returns 0 in that case.
    """
    keep = {tid for tid in keep_thread_ids if tid}

    if not CHECKPOINT_DB_FILE.is_file():
        return 0

    conn = sqlite3.connect(str(CHECKPOINT_DB_FILE), check_same_thread=False)
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        try:
            rows = conn.execute("SELECT DISTINCT thread_id FROM checkpoints").fetchall()
        except sqlite3.OperationalError as err:
            # Table not created yet, OR async writer holds the lock past our
            # busy_timeout. Either way, prune is not urgent — skip and let
            # the next call retry rather than crashing the UI.
            logger.debug("prune_threads: skipping (sqlite said %s)", err)
            return 0

        existing = {row[0] for row in rows if row and row[0]}
        to_delete = existing - keep
        if not to_delete:
            return 0

        deleted = 0
        for thread_id in to_delete:
            try:
                conn.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
                conn.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
                deleted += 1
            except sqlite3.OperationalError as err:
                # Lock contention with the async writer. Leave this thread
                # for the next prune pass; do not abort the rest.
                logger.warning(
                    "prune_threads: skipping %s due to lock (%s)", thread_id, err
                )
            except Exception as err:
                logger.warning("Could not prune thread %s: %s", thread_id, err)

        try:
            conn.commit()
        except sqlite3.OperationalError as err:
            logger.warning("prune_threads: commit failed (%s); rolled back", err)
            conn.rollback()
            return 0

        if deleted:
            logger.info("Pruned %d evicted chat thread(s) from checkpoint DB", deleted)
        return deleted
    finally:
        conn.close()
