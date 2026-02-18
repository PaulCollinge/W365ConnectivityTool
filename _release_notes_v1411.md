## v1.4.11 — Fix NAT Type Detection

### Bug Fixes

**Browser test (B-UDP-02)** — fundamental fix:
- Was using **two separate `RTCPeerConnection` instances**, each creating its own UDP socket. Different sockets naturally get different external port mappings even on a Cone NAT, so the test almost always reported "Symmetric NAT".
- Now uses a **single `RTCPeerConnection`** with both STUN servers in the `iceServers` list. The browser sends from one socket to both servers. For Cone NAT, the reflexive candidates are de-duplicated (same mapping). For Symmetric NAT, two distinct reflexive endpoints appear.
- Added `relatedAddress`/`relatedPort` extraction to `parseCandidate()` for proper base-socket grouping.

**Scanner test (L-UDP-05)**:
- Replaced non-responsive secondary STUN server `13.107.17.41:3478` with `stun1.l.google.com:19302`, resolved dynamically at runtime with fallback IP.

### SHA256
```
F4757EA07D101E115E93D5D984B84BA77799F2C5190CFB2102DE523688AB7FBF
```
