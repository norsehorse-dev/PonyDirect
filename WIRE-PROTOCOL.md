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
this protocol.

### Candidate gathering (STUN, RFC 5389)

Each device binds one UDP socket and gathers two kinds of candidate on that socket's
local port:

- Host candidates: every non-loopback local IPv4 `ip:port`.
- Server-reflexive candidate: the public `ip:port` the socket maps to, learned with
  one STUN Binding request to the app's self-hosted STUN server.

Binding request (20 bytes, no attributes):

    type(2)=0x0001 | length(2)=0x0000 | magic(4)=0x2112A442 | transaction_id(12, random)

Binding success response `type=0x0101`; the client matches `magic` and
`transaction_id`, then reads XOR-MAPPED-ADDRESS (attribute `0x0020`), falling back to
MAPPED-ADDRESS (`0x0001`). For XOR-MAPPED-ADDRESS the port is `x_port XOR (magic >> 16)`
and an IPv4 address is `x_addr XOR magic` (IPv6 XORs `magic || transaction_id`). STUN
only reflects the socket's public address; it sees no application content.

### Punch datagrams

The gathered candidates go to the peer over signaling. Both sides then send
authenticated datagrams to each other's candidates on the same UDP socket and listen.
Datagrams are self-delimiting, so there is no length prefix - a one-byte type leads:

    0x11 PROBE      session_nonce(16) | probe_nonce(16) | tag(32)
    0x12 PONG       session_nonce(16) | probe_nonce(16) | tag(32)
    0x13 KEEPALIVE  session_nonce(16)

    PROBE.tag = HMAC(K, "ponydirect/wan-probe/v1" || session_nonce || probe_nonce)
    PONG.tag  = HMAC(K, "ponydirect/wan-pong/v1"  || session_nonce || probe_nonce)

A PONG echoes the PROBE's `probe_nonce` so the prober can match it. A path is
established once a peer answers a PROBE with a valid PONG, or once a valid PROBE is
received (which proves the peer can reach this socket); the datagram's source address
becomes the active remote. The first candidate that yields a verified packet wins.
KEEPALIVE (unauthenticated NAT-hold traffic) is sent on the active path every ~15 s.

Only the real peer can produce a valid PROBE or PONG, so an off-path or spoofed
sender cannot hijack the path; `session_nonce` binds the exchange so a captured probe
cannot be replayed into a new session. Symmetric NAT on both ends will not punch; the
host app falls back to its own store-and-forward path (no TURN).

## Delivery

On the LAN TCP stream a payload is a single `0x04 ENVELOPE` frame. On the
hole-punched UDP path a payload is split into authenticated chunks with a small
ACK/retransmit layer, since UDP has no ordering or reliability of its own:

    0x14 DATA  session_nonce(16) | msg_seq(4) | chunk_index(2) | chunk_count(2) | payload | tag(32)
    0x15 ACK   session_nonce(16) | msg_seq(4) | chunk_count(2) | bitmap | tag(32)

    DATA.tag = HMAC(K, "ponydirect/wan-data/v1" || session_nonce || msg_seq ||
                       chunk_index || chunk_count || payload)
    ACK.tag  = HMAC(K, "ponydirect/wan-ack/v1"  || session_nonce || msg_seq ||
                       chunk_count || bitmap)

All integers are big-endian. Each chunk carries at most 1024 payload bytes, so a
DATA datagram stays well under a safe path MTU. `msg_seq` is chosen by the sender
and identifies one message; `bitmap` has `ceil(chunk_count/8)` bytes, bit `i` set
meaning chunk `i` was received. The sender transmits every chunk, the receiver ACKs
the bitmap of what it holds, and the sender retransmits only the gaps on a timer
until every chunk is acked or a deadline passes (after which the app's relay path
covers it). The receiver reassembles chunks `0..chunk_count-1` in order and hands
the bytes to the app; it remembers recently completed `msg_seq`s so a retransmit
after its ACK was lost is re-acked, not re-delivered. Every DATA and ACK is tagged
with the per-pair key, so only the real peer can inject or acknowledge chunks. A
per-message size cap (256 chunks, 256 KB) bounds reassembly; larger payloads are
left to the relay. The reassembled bytes are opaque and already end-to-end secured
by the app; PonyDirect adds transport, not confidentiality.
