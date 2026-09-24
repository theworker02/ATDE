# ADR-0002: NATS JetStream as threat bus

## Status

Accepted (v0.1.0)

## Context

Trap → Extract → Trace → Disrupt needs durable, replayable decoupling. In-process channels couple failure domains; Redis lists lack first-class consumer groups and retention semantics we want for evidence.

## Decision

Use **NATS JetStream** stream `THREAT_PIPELINE` with subjects `threat.v1.raw.*`, `threat.v1.artifact.*`, `threat.v1.action.*`, durable consumers, and a DLQ subject.

## Consequences

- Horizontal scale of workers by mode  
- Replay for forensics  
- Operational dependency on JetStream (Compose ships it)  
- Contract docs in `docs/contracts/BUS.md` + JSON schemas  
