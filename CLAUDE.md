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

Scaffolding inicial. La especificación funcional llega en el siguiente prompt del usuario.
