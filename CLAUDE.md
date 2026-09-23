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
- **Fase 4 ✅** — su criterio del roadmap ("Register → bind → attest works end to end") corre
  como test: `TestRegisterBindAttestEndToEnd`. Incluye `internal/store`, `internal/api`,
  `services/gateway`, registro con doble desafío (§8), emisión de credenciales (§8.2) y
  binding con prueba de continuidad (§9).

  **Cadena unificada:** registro, binds, unbinds, rebinds y acciones viven todos en
  `agent_chain_events`. El registro es la secuencia 1, así que la primera acción es la 2. La
  regla de fork cubre ahora todo tipo de evento, no solo acciones.

  Atestiguar exige `ACTIVE`, y a `ACTIVE` se llega bindeando un runtime.
- **Fase 6 ✅** — motor de políticas. `pkg/policy` (verificación de bundles: hash, M-de-N,
  cadena de versiones — sin dependencias), `internal/pdp` (OPA embebido), el bundle
  `policy/gasc-2027.4` firmado 3-de-5, y `POST /v1/policy/evaluate` que firma y persiste cada
  decisión con versión y hash de bundle (INV-009).

  **El bundle commiteado trae su manifest y sus firmas; las claves de gobernanza no.** Editar
  una regla o un umbral rompe `make policy-verify` hasta que alguien con esas claves lo vuelva
  a firmar. La política no la cambia quien tiene acceso de escritura al repo.
- **Fase 7 ✅** — los 7 contratos (`contracts/src/`, 31 tests Foundry con fuzzing), el servicio
  de transparencia (`internal/translog`: log persistente, recibos SCITT, co-firma de witnesses),
  el cliente de cadena (`internal/chain`, JSON-RPC mínimo) y el ledger-writer
  (`services/ledger-writer`). El pipeline se prueba contra una EVM real con `anvil`.

  **INV-007/008 es un gate del build**, no una revisión de código: `test/onchain` lee las ABIs
  commiteadas en `spec/contracts/` y rechaza cualquier parámetro que no sea de ancho fijo.

  **El adaptador `noop-dev` no fabrica anclas.** Devuelve un error, no un hash plausible: un
  build de desarrollo que inventara una transacción haría que los recibos afirmen una
  durabilidad que nadie proveyó, y el reclamo sería indistinguible de uno real hasta que
  alguien fuera a buscar esa transacción.

  **Los witnesses locales dan el mecanismo, no la independencia.** La detección de vista
  dividida se apoya en que los witnesses los opere gente que no se coludiría con el log, y dos
  goroutines no son eso. §18.3 da 2 locales para el MVP y ≥3 operadores independientes en
  producción; el mecanismo está implementado y testeado para lo segundo.

- Fases 8–12: sin empezar.

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
11. **La clave del emisor nunca se genera al arrancar.** Una clave que cambia en cada reinicio
    emite credenciales que dejan de verificar, y el operador se entera por fallas de
    verificación en vez de por un error de arranque. `make issuer-key` la crea una vez, y el
    gateway se niega a arrancar sin ella.
12. **Todo lo que le pasa a una identidad va a la misma cadena.** Si un cambio de estado no
    está en `agent_chain_events`, quien recorre la historia no lo ve, y el estado al momento
    del evento hay que sacarlo de una segunda fuente — que es justo el trabajo que una cadena
    de hashes existe para evitar.
13. **Auditar una decisión pasada nunca puede requerir la maquinaria que la tomó.** Por eso
    `pkg/policy` verifica bundles sin dependencias y OPA vive solo en `internal/pdp`: quien
    audita corre el camino liviano, quien decide carga los 33 módulos (ADR-0002).
14. **Nada que pueda cargar contenido entra a un contrato.** No es una regla de revisión: es
    un test sobre las ABIs commiteadas. Si un parámetro no es de ancho fijo, el build falla.
15. **Un adaptador que no publica nada tiene que PARECER que no publica nada.** Nunca devolver
    un identificador plausible por algo que no ocurrió: la evidencia falsa es peor que la
    evidencia ausente, porque la ausente se nota.
16. **Una credencial tiene que valer sin nosotros.** Si validarla exige preguntarle algo a UAI,
    es una respuesta de API con pasos extra, y devuelve el uptime y la honestidad de UAI a la
    ecuación de confianza que el protocolo existe para sacarlas.
