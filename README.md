# PonyDirect

A small, dependency-free peer-to-peer transport for already-paired peers. It
delivers opaque application bytes two ways:

- **LAN-direct**: find a paired peer on the same network by mDNS and exchange
  sealed envelopes over a direct TCP connection.
- **WAN-direct**: reach a paired peer across the internet by STUN + UDP hole
  punching, with the application's own channel used only to introduce the two
  peers.

Both paths authenticate the peer with a short handshake keyed on a symmetric
secret the two sides already share, so a passive observer or a stranger's device
learns nothing. PonyDirect carries opaque bytes; **the application owns the
encryption and the key exchange.** In [CarrierPony](https://carrierpony.com) the
bytes are already-sealed (roster-hiding) envelopes.

## Why it exists

It is the direct-delivery layer factored out of CarrierPony so other apps
(device-to-device transfer, and the rest of the family) can reuse it and so the
transport and its wire crypto can be audited on their own. It is deliberately
**not** a WebRTC reimplementation: no media, no congestion control, no full ICE.
It is dependency-free and builds from source on a plain toolchain, which is what
lets an app that ships it still go through F-Droid's build server.

## The boundary

The app plugs in three things and PonyDirect does the rest:

- `PonyDirectKeyProvider` - a stable 32-byte symmetric key per peer (both sides
  derive the same value out of band). Used only for the handshake and probe MACs;
  the library never sees the app's raw keys.
- `PonyDirectSignaling` - the app's own confidential channel for relaying the
  WAN offer/answer/ICE candidates (CarrierPony sends them as sealed control ops,
  so its relay only ever sees opaque traffic).
- `PonyDirectEnvelopeSink` - where delivered payloads arrive.

Local-network discovery (mDNS) is supplied by the app through
`PonyDirectDiscovery`, because it needs platform APIs; everything else is
platform-neutral.

## Status

Early. The wire crypto, framing, and the application boundary are in place and
unit-tested. The LAN and WAN transports are being built against CarrierPony and
land here as they stabilize. The wire protocol is specified in
[`WIRE-PROTOCOL.md`](WIRE-PROTOCOL.md) and is the contract shared with the Kotlin
implementation (`PonyDirect-Kotlin`).

## Layout

- `Sources/PonyDirect/PonyDirectWire.swift` - framing + the authenticated tags.
- `Sources/PonyDirect/PonyDirect.swift` - the application boundary.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
