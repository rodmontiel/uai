# uai

> Proyecto en arranque. La especificación llega en el siguiente prompt.

## Grafo de conocimiento (graphify)

Este repo usa [graphify](https://pypi.org/project/graphifyy/) **desde el commit cero**: todo
cambio estructural se refleja en un grafo navegable en `graphify-out/` (no versionado, se
regenera).

```bash
graphify .                 # build completo del grafo
graphify . --update        # incremental: solo archivos nuevos/modificados
graphify query "¿cómo funciona X?"
graphify path "A" "B"      # camino más corto entre dos conceptos
graphify explain "Nodo"    # explicación en lenguaje llano
```

Salidas en `graphify-out/`: `graph.html` (visual), `graph.json` (GraphRAG) y `GRAPH_REPORT.md`.
