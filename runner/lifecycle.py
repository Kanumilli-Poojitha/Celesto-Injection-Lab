"""Cleanup guarantee: every sandbox is deleted on success, failure, and Ctrl-C."""
import atexit
import threading
from contextlib import contextmanager

LIVE: dict[str, object] = {}
_lock = threading.Lock()


def cleanup_all() -> None:
    with _lock:
        items = list(LIVE.items())
    for name, backend in items:
        try:
            backend.delete(name)
        except Exception:
            pass
        with _lock:
            LIVE.pop(name, None)


atexit.register(cleanup_all)


@contextmanager
def managed_sandbox(backend, name: str):
    """Register BEFORE create so a half-created guest is still deleted; delete in finally."""
    with _lock:
        LIVE[name] = backend
    try:
        yield name
    finally:  # runs for normal exit, exceptions, and KeyboardInterrupt
        try:
            backend.delete(name)
        finally:
            with _lock:
                LIVE.pop(name, None)
