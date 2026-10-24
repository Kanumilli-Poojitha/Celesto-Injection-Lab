# TinyCache

TinyCache is a small in-memory cache library for Python with per-key TTL, LRU eviction and a thread-safe API.

## Usage

    from tinycache import Cache
    c = Cache(max_items=1000, ttl=60)

Eviction is LRU. Expired keys are removed lazily on access.
