# ADR-0001: Local-first containment, fail-soft cloud

## Status

Accepted (v0.1.0)

## Context

Cloud WAF APIs (Cloudflare, AWS WAFv2) are valuable but optional: tokens expire, rate limits trip, and air-gapped or bootstrap nodes have no credentials. Operators still need immediate containment when a scanner hits a decoy.

## Decision

`EnforceContainment` always attempts **OS-level block first** (when enabled and IP is public). Cloud integrations run **asynchronously** and **never fail the pipeline**.

## Consequences

- Guaranteed defensive action without SaaS dependency  
- Cloud errors become warnings, not NATS poison-pills  
- Requires host privilege (`NET_ADMIN` / Administrator) documented in DEPLOY.md  
