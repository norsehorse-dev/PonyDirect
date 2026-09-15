# PonyDirect wire protocol v1

The byte-exact contract shared by the Swift and Kotlin implementations. Any change
to these bytes bumps the version and lands in both at once.

## Per-peer key

The application supplies one stable 32-byte symmetric key `K` per peer, the same
value on both sides, derived out of band from whatever the app already shares. In
CarrierPony that derivation is `HMAC-SHA256("cp-lan-v1", lexsort(myInboundKey,
peerInboundKey))` over the sealed-sender pair keys, but PonyDirect does not care
how `K` is produced - it only uses `K` for the MACs below. HMAC-SHA256 is the only
primitive.

## Framing

Every connection or stream opens with the 4 ASCII bytes `PDR1`. After that, frames:

    type(1) | length(4, big-endian) | payload(length)

    0x01 HELLO       dialer -> listener   (LAN identify request)
    0x02 HELLO_ACK   listener -> dialer   (identified)
    0x03 NO_MATCH    listener -> dialer   (not a known peer; ack-shaped padding)
    0x04 ENVELOPE    either -> either     (one opaque application payload)

## LAN identify handshake

Roster-hiding: mDNS advertises only a per-launch random node id, never an identity.
On connect:

- HELLO payload   = dialer_nonce(16) || tag, where
      tag = HMAC(K, "ponydirect/id/v1" || dialer_nonce)
  The dialer names exactly one target peer per connection, so a connection reveals
  at most "someone is looking for one of my peers", and only the real target can
  tell it is them.
- The listener recomputes the tag for each of its known peers; a match identifies
  the dialer. Reply:
      HELLO_ACK payload = listener_nonce(16) ||
          HMAC(K, "ponydirect/id-ack/v1" || dialer_nonce || listener_nonce)
  No match: reply NO_MATCH with 48 random bytes (same shape as an ack) and close,
  so length reveals nothing to a passive observer.

## WAN hole punching

Signaling (offer/answer/ice, carrying an `ip:port` candidate list and a 16-byte
`session_nonce`) travels over the application's own confidential channel, not over
this protocol. Once candidates are exchanged, both sides send authenticated probes
to each other's candidates and listen:

    probe = probe_nonce(16) || HMAC(K, "ponydirect/wan-probe/v1" || session_nonce || probe_nonce)
    pong  =                     HMAC(K, "ponydirect/wan-pong/v1"  || session_nonce || probe_nonce)

The first candidate pair that yields a valid pong is the active path. Only the real
peer can produce a valid probe or pong, so an off-path or spoofed sender cannot
hijack the path; `session_nonce` binds the exchange so a captured probe cannot be
replayed into a new session. Symmetric NAT on both ends will not punch; the host
app falls back to its own store-and-forward path (no TURN).

## Delivery

Application payloads move as `0x04 ENVELOPE` frames over whichever path is up
(LAN TCP stream, or the hole-punched UDP path with a small reliability layer for
chunking large payloads). The payload is opaque and already end-to-end secured by
the app; PonyDirect adds transport, not confidentiality.
