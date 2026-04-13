# av-api

Shared audio ingest and orchestration helpers for Wavey API services.

This crate sits above `upload-response` and `soundkit`:

- `soundkit` owns PCM/sample-format conversion
- `upload-response` owns transport/session caching
- `av-api` owns reusable audio ingest state that API services can compose
