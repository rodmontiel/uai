# ADR-0001 · Rootless Podman as the reference container runtime

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** decided during Phase 4, applies from Phase 4 onward
- **Supersedes:** the aspirational `deploy/compose/docker-compose.yml` introduced in Phase 0

---

## 1 · The question

Containerisation was going to happen either way. The real question was **when**: now, while
one service exists, or after Phase 12, when roughly ten do.

The tempting answer is "later" — containers look like packaging, and packaging is the last
step. That answer is wrong for this project specifically, for the reason in §3.2.

## 2 · Decision

1. **Rootless Podman is the reference runtime, from this commit.** Every container target in
   the `Makefile` detects the runtime and prefers `podman`; `make CONTAINER=docker <target>`
   remains supported and tested on every target.
2. **Infrastructure is containerised now.** `deploy/compose/compose.yaml` holds the services
   the code actually uses today — PostgreSQL, and nothing else.
3. **Service images arrive in the phase that builds the service.** `uai-gateway` has a
   `Containerfile` today because the binary exists. The other fifteen directories under
   `services/` do not, and will not get one until they contain code.
4. **Kubernetes stays in Phase 12**, as the roadmap already says. This ADR does not move it.

## 3 · Rationale

Ordered by the project's own priority list: `security > auditability > interoperability >
simplicity > performance > visual polish`.

### 3.1 Security — measured, not asserted

Both runtimes were installed on the development machine when this was decided, so the
comparison is an observation rather than a citation:

| | Podman (rootless) | Docker |
|---|---|---|
| Owner of the container process **on the host** | uid `100069` — an unprivileged subuid | namespaced by a daemon running as `root` |
| Long-lived privileged process | none | `dockerd`, as `root`, always |
| Access model | the invoking user's own privileges | membership in the `docker` group, which is root-equivalent |

A project whose entire thesis is verifiable identity and least privilege should not require a
root-equivalent group membership to run its own test suite. This is not hypothetical: threat
**T-07** is supply-chain compromise, and a hostile `postgres` or `opa` image under Docker gets
a root daemon to talk to, while under rootless Podman it gets an unprivileged subuid with no
standing on the host.

### 3.2 The runtime is part of the trust chain, not part of packaging

This is the argument that settles the timing, and it is specific to UAI.

Phase 12 introduces SPIFFE/SPIRE ([§23.5](../protocol/16-deployment.md)). SPIRE does not take a
workload's word for who it is — it derives identity from what the **runtime** can attest about
the process. Workload attestor plugins and their selectors are therefore runtime-specific:

```text
docker:label:com.acme.service:gateway      Docker attestor
unix:uid:65532 / systemd:id:uai-gateway    rootless Podman, via the unix and systemd attestors
k8s:sa:uai-gateway / k8s:pod-image:...     Kubernetes attestor
```

Deferring the runtime choice until after the SPIFFE integration is written means **choosing the
root of the workload trust chain after building on top of it**. Every registration entry, every
selector and every attestation test would have to be rewritten, and the rewrite would be to the
part of the system that decides which process is allowed to be `uai-gateway` at all.

For an ordinary web application the runtime really is packaging and really can wait. Here it is
the base of the identity chain, so it cannot.

### 3.3 The existing stack was already wrong, and waiting meant leaving it wrong

`deploy/compose/docker-compose.yml` declared `redis`, `nats`, `minio` and `opa`. A grep of the
Go sources found **zero** references to any of them: the nonce cache is PostgreSQL
(`internal/store`), there is no message bus, no object store, and the policy engine is Phase 6.

That is project rule 8 — *never state in the present tense what does not exist yet* — broken in
the most expensive file to break it in, because it is the first command a new contributor runs.
The same defect was already found and fixed twice in prose (§23.4, §7.9). "Containerise later"
would have meant leaving the third instance standing in executable form.

### 3.4 Interoperability and the cost curve

One service to migrate today; ten by Phase 12 (four Besu validators, two witnesses, SPIRE
server and agent, OPA, the frontend). Migration cost grows with every phase, and the phases that
add the most services are exactly the ones where the runtime's attestation semantics matter most.

Podman additionally has a supported path to the Phase 12 target — `podman generate kube` and
Quadlet systemd units — which Compose does not. That is a convenience, not a reason; §3.2 is
the reason.

## 4 · What this deliberately does not do

- **No images for the fifteen empty `services/` directories.** That would be §3.3 again, in a
  new file.
- **No Kubernetes manifests.** Phase 12, unchanged.
- **No Besu, SPIRE, OPA or witness containers.** Phases 7, 12 and 6 respectively. They enter the
  compose file when code talks to them, not before.
- **No removal of Docker support.** Every target runs under both, and CI should exercise both:
  a reference implementation that only runs on the runtime its authors happen to prefer has
  quietly narrowed the protocol.

## 5 · Consequences

**Accepted costs.**

- Rootless Podman cannot bind ports below 1024 without extra configuration. Nothing in the
  stack needs to; if something ever does, it is a signal that a service is being run in a way
  production will not.
- `podman compose` delegates to the Compose binary over the rootless podman socket. The
  Makefile prefers `podman-compose`, which drives Podman directly and needs no socket at all,
  and falls back to starting the socket with a clear message rather than the runtime's own
  `dial unix ... no such file` error.
- Container names differ between providers (`uai_postgres_1` vs `uai-postgres-1`). Everything
  therefore addresses containers through the compose provider or by an explicit `--name`, never
  by a guessed generated name.

**Gains that are verified, not claimed.** Each of these is an executable check:

| Property | How it is proven |
|---|---|
| Rootless | `make runtime` prints the runtime's own `Host.Security.Rootless` |
| Reproducible image | two consecutive `make image` runs yield an identical image id |
| No shell in the image | `podman run --entrypoint /bin/sh` fails: the file does not exist |
| Fails closed | the gateway with no `PG_DSN` logs and exits instead of assuming a default |
| Dev and test run the same database | `PG_IMAGE` is parsed out of `compose.yaml`, so the throwaway integration database cannot drift from the dev stack |

## 6 · Related

- [§23.4 Local development](../protocol/16-deployment.md) — the phase-by-phase service table
- [§23.5 Production](../protocol/16-deployment.md) — Kubernetes + SPIRE, Phase 12
- [§20 Threat model](../protocol/13-threat-model.md) — T-07 supply chain
