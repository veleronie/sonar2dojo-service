import threading



_seen = set()

_lock = threading.Lock()



def is_processed(key: str) -> bool:

    with _lock:

        return key in _seen



def mark_processed(key: str):

    with _lock:

        _seen.add(key)