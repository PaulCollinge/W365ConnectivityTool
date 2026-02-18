## v1.4.10 — Fix AFD PoP Parsing

### Bug Fix
- **Fixed "could not parse from Edge Ref"** — The regex extracting the AFD PoP code from `X-MSEdge-Ref` headers now correctly handles digits between the PoP code and "Edge" suffix (e.g. `BCN30EDGE0409` → `BCN` = Barcelona)
- Scanner regex: `([A-Z]{2,5})Edge` → `([A-Z]{2,5})\d*Edge`
- Browser regex updated to match 2–5 letter PoP codes consistently
- Map card now gracefully falls back when PoP parsing fails

### SHA256
```
5A8D1FE3E4D9B2398F072762D2F8551A05C8C3872950D489FDFF9C87A71FBDB8
```
