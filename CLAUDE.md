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

Spec v0.1 completo en `docs/protocol/` (26 secciones). Implementación por fases:

- Fase 2 (parcial): `pkg/uaiid`, `pkg/uaicrypto`, `pkg/merkle` — con tests, sin dependencias externas.
- Fase 3: schema PostgreSQL (`db/migrations/`) + invariantes ejecutables (`test/invariants/`).

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
