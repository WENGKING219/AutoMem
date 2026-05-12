"""
Persistent LangGraph storage for chat checkpoints and agent memories.

The UI can reopen recent chats, so each Streamlit thread needs a matching
LangGraph checkpoint on disk. AsyncSqliteSaver gives us that persistence while
still supporting the async streaming APIs used by the agent.

Only the active thread is loaded into the model context. Older sidebar chats
remain in SQLite until the UI prunes them, and summarization keeps each active
thread bounded.
"""

import asyncio
import logging
import sqlite3

import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.store.memory import InMemoryStore

from config.settings import CHECKPOINT_DB_FILE

logger = logging.getLogger("forensics_agent")

# Module-level cache so callers share one checkpointer and SQLite connection.
# The saver is tied to the event loop that created it, so Streamlit reruns and
# hot reloads need a fresh saver when the loop changes.
_checkpointer = None
_checkpointer_loop = None
_store = None


async def _configure_async_pragmas(conn: aiosqlite.Connection) -> None:
    """Configure SQLite pragmas for better concurrency and reliability with async writes."""
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
    """Return the shared AsyncSqliteSaver for `/checkpoints/`, creating it if needed."""
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
        # The event loop changed, so drop the stale saver. Closing the old
        # connection on its original loop releases SQLite handles promptly on
        # Windows, where waiting for GC can leave the next sync prune locked.
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
        # This function is sync, so schedule pragma setup on the running loop.
        # The caller yields while building the agent before the first write.
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
    checkpointer has any rows - returns 0 in that case.
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
            # busy_timeout. Either way, prune is not urgent - skip and let
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
