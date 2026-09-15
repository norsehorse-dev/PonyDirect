# Contributing

PonyDirect is developed against real use in the CarrierPony apps and kept
byte-compatible across its Swift and Kotlin implementations. The wire protocol in
`WIRE-PROTOCOL.md` is the contract; any change to the bytes must land in both
implementations together and bump the wire version.

- Keep it dependency-free. The whole point is that it builds from source on a
  plain toolchain (no prebuilt native blobs), so it can go through F-Droid's build
  server as part of an app that uses it.
- Keep it narrow. This is a sealed P2P transport, not a WebRTC reimplementation:
  no media, no congestion control, no full ICE. The always-present relay in the
  host app is the fallback when traversal fails.
- The library never sees the application's raw keys. It takes one 32-byte
  per-peer symmetric key through `PonyDirectKeyProvider` and uses it only for the
  handshake and probe MACs.
