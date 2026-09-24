# ADR-0003: Explicit offensive non-goals

## Status

Accepted (v0.1.0)

## Context

“Active defense” language often slides into hacking-back: flooding exfil channels with stolen tokens, poisoning third-party botnets’ peer tables. That creates CFAA/ToS risk and poisons acquisition diligence.

## Decision

ATDE **does not** implement live third-party Telegram/webhook abuse or live Mirai/Hajime DHT injection. Those paths remain **evidence simulation only**. Containment is limited to owned edge / legitimate abuse APIs.

## Consequences

- Cleaner legal packaging for buyers  
- Some “Phase 4 fantasy” features stay simulated—documented, not hidden  
- Product differentiation is **catch & contain**, not counter-attack  
