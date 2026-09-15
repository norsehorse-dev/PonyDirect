# Security Policy

## Reporting a vulnerability

Email **NorseHorse@norsehor.se** with details and, if possible, a proof of
concept. Please do not open a public issue for security-sensitive reports.

You can expect an acknowledgement within a few days. Coordinated disclosure is
appreciated: give a reasonable window for a fix before any public write-up.

## Scope

This repository is the peer-to-peer transport: the wire crypto (the authenticated
identify handshake and hole-punch probes), the framing, and the NAT-traversal
logic. It carries opaque application bytes and never handles application key
material beyond the single per-peer symmetric key the app hands it. The
confidentiality and authenticity of the payload are the application's
responsibility, not this library's.
