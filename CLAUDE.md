# CLAUDE.md — uai

## Regla 0: graphify primero

Este proyecto se construye con un grafo de conocimiento vivo desde el commit inicial.

**Antes de responder cualquier pregunta sobre el código o la arquitectura:**
si existe `graphify-out/graph.json`, tratá la pregunta como una query del grafo
(`graphify query "<pregunta>"`) antes de ponerte a leer archivos sueltos.

**Después de cada cambio estructural** (archivos nuevos, módulos nuevos, refactors,
cambios de dependencias) corré:

```bash
graphify . --update
```

y si el cambio fue grande (o el reporte quedó desactualizado), un build completo:

```bash
graphify .
```

`graphify-out/` está en `.gitignore`: es derivado y se regenera. El intérprete ya quedó
fijado en `graphify-out/.graphify_python`.

## Estado

Spec v0.1 completo en `docs/protocol/` (26 secciones). El numerado de fases sigue
`docs/protocol/19-roadmap.md` al pie de la letra: una fase es ✅ solo cuando su entregable
declarado existe en el repo.

- **Fase 2 ✅** — 10 JSON Schemas con 40 ejemplos, 3 contextos JSON-LD, OpenAPI 3.1 (21 paths),
  9 sets de vectores normativos y `tools/uai-conformance` (125 chequeos).
- **Fase 3 ✅** — schema PostgreSQL (`db/migrations/`) + 35 invariantes ejecutables
  (`test/invariants/invariants.sql`; hoy 47).
- **Fase 5 ✅** — `pkg/uaiid`, `pkg/uaicrypto`, `pkg/merkle`, `pkg/pop` (PoP RFC 9421),
  `pkg/keys` (rotación, compromiso, validez al momento del evento), `pkg/receipt`
  (checkpoints, receipts, co-firma de witnesses).
- **Fase 4 🟡** — `internal/store` (persistencia con cadena de eventos atómica), `internal/api`
  (problem+json, middleware de PoP e idempotencia, handlers de attestation y verificación),
  `services/gateway`, y el **flujo de registro completo** (§8: doble desafío owner+agente,
  `pkg/challenge`, thumbprint RFC 7638 en `pkg/uaicrypto`, migración 0003). Faltan binding
  (§9: BIND/UNBIND/REBIND) y emisión de credenciales.

  **Hueco conocido, a cerrar con binding:** `statusRefusal` deja atestiguar a un agente en
  `REGISTERED`. Según §6.10 las acciones salen de `ACTIVE`, y llegar a `ACTIVE` exige binding
  de runtime. Exigir `ACTIVE` hoy dejaría la attestation inalcanzable hasta que exista binding,
  así que se cierra junto con él y no antes.
- Fases 6–12: sin empezar.

`make integration` levanta Postgres, migra, siembra y corre los tests de store y API con
`-race` más las 35 aserciones de invariantes.

`make check` corre todo: build, lint, tests, conformance y reproducibilidad de vectores.

**Runtime de contenedores: Podman rootless** (ADR-0001). `make runtime` dice qué detectó.
Docker sigue soportado en todos los targets con `make CONTAINER=docker ...`, y tiene que seguir
funcionando: una implementación de referencia que solo corre en el runtime que prefieren sus
autores angostó el protocolo sin decirlo.

## Reglas del proyecto

1. **Prioridad en cada trade-off:** security > auditability > interoperability > simplicity >
   performance > visual polish.
2. **Nunca prometer un kill switch global.** Revocación = los participantes dejan de honrar la
   credencial. Si un texto de UI, una respuesta de API o un doc implica otra cosa, es un bug.
3. **`pkg/` no toma dependencias externas** sin justificación explícita: está en el camino de
   verificación y cada dependencia ahí es superficie de supply-chain (amenaza T-07).
4. **Cada invariante INV-001..010 necesita un test negativo** que pruebe que la operación
   prohibida falla. No alcanza con documentarla.
5. **Nada de contenido en la blockchain ni en el log**: solo commitments salteados.
6. **Los vectores de `spec/test-vectors/` se leen, no se regeneran en los tests.** Un test que
   escribe sus propias expectativas solo prueba que el código se cree a sí mismo. Regenerarlos
   (`make vectors`) debe ser un no-op: un diff significa que cambió el protocolo.
7. **Todo schema necesita ejemplos inválidos.** Un schema que nunca rechaza nada no valida nada.
8. **No afirmar en presente lo que todavía no existe.** Ya pasó tres veces: el texto del compose
   (§23.4), los test vectors (§7.9) y el compose real, que declaraba `redis`, `nats`, `minio` y
   `opa` sin que ninguna línea de Go los mencionara. Si un doc o un archivo ejecutable describe
   algo no implementado, decir en qué fase entra.
9. **El compose y el `.env.example` solo listan lo que el código usa hoy.** Son el primer
   comando que corre alguien nuevo; ahí la regla 8 es más cara que en prosa.
10. **Ninguna imagen puede depender de una feature de build específica de un vendor.** Las
    imágenes son OCI, se construyen rootless y el build tiene que ser reproducible: dos `make
    image` seguidos dan el mismo image id.
