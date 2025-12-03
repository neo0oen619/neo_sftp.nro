## neo_sftp – download pipeline ideas

Goal: make large remote downloads faster and more reliable by fetching multiple chunks of a file concurrently, then stitching them back together on the Switch.

Status (2025‑12‑03): the core per‑file WebDAV chunking + parallelism is implemented and wired to INI options. The remaining ideas here are mostly cross‑protocol or UI polish.

### High-level idea

- Keep the existing sequential download path as a safe fallback.
- Add an optional "parallel chunked download" mode:
  - Split a file into N chunks of size `chunk_size_mb` (configurable).
  - For each chunk, issue a ranged HTTP/SFTP/WebDAV request:
    - WebDAV/HTTP: use `Range: bytes=start-end`.
    - SFTP: use multiple read requests in flight if feasible.
  - Download several chunks at once (limited concurrency, e.g. 2–4 workers).
  - Write chunks into the final file at the correct offsets.

### Configuration sketch (INI)

- `[Global]`
  - `download_parallel_enabled` (bool, default `false`):
    - `false`: current sequential behaviour.
    - `true`: enable multi-chunk downloads where supported.
  - `download_parallel_workers` (int, default 2, clamp 1–4):
    - Number of concurrent chunk workers per file.
  - `download_chunk_mb` (int, default 8, clamp 1–32):
    - Target chunk size per request.

### Implementation notes (future work)

- WebDAV/HTTP (mostly done):
  - Implemented ranged GETs via `GetRangedSequential` / `GetRangedParallel` and their split variants in `WebDAVClient` using `CHTTPClient`.
  - Managed workers via a small pool of threads, one `CHTTPClient` per worker, coordinated through `WebDAVParallelContext` / `WebDAVParallelSplitContext`.
  - Enforced a 256 MiB in‑flight window to keep RAM usage bounded, controlled by `[Global] webdav_chunk_mb` and `[Global] webdav_parallel`.
  - Added per‑chunk retries and, at the file level, automatic retries with backoff before asking the user to confirm.

- Local file writes:
  - Open the destination file once, pre-size it to the full length (when size is known).
  - Use `fseek/ftello` (or equivalent) to write each chunk at its offset.
  - Guard writes with a mutex if multiple threads share the same `FILE*`, or give each worker its own descriptor.

- Progress reporting:
  - Keep a shared `bytes_downloaded` counter updated atomically as chunks complete.
  - UI can continue to read aggregate progress the same way it does today.

### Safety and constraints

- Switch has limited CPU/RAM; defaults must stay conservative:
  - Low default worker count.
  - Moderate chunk size to avoid huge allocations.
- Network stacks (VPN/WebDAV/proxies) may rate-limit or dislike too much parallelism:
  - Implementation should detect repeated failures and fall back to sequential mode.

### New TODOs after first implementation

- Extend similar multi‑chunk / parallel semantics to SFTP (libssh2 pipelining or multiple handles), with conservative defaults and a separate INI section.
- Add more UI around multiple active transfers (simple “Transfers” list, per‑file status) while keeping the existing global bar lightweight.
- Consider per‑site performance presets so aggressive LAN settings don’t leak into slow WAN sites.

This file now tracks *future* pipeline ideas; see `webdav_downloads.md` for the current WebDAV implementation.
