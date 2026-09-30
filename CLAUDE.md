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

- **Fase 2 ✅** — 10 JSON Schemas con 41 ejemplos, 3 contextos JSON-LD, OpenAPI 3.1 (24 paths),
  13 sets de vectores normativos y `tools/uai-conformance` (161 chequeos).
- **Fase 3 ✅** — schema PostgreSQL (`db/migrations/`) + invariantes ejecutables
  (`test/invariants/invariants.sql`; hoy 86).
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

- **Fase 8 ✅** — las seis superficies en `web/` (home, verify, passport, explorer, cuarentena,
  gobernanza) y `services/web`, que sirve un solo origen con CSP estricta y proxea `/v1` para no
  necesitar CORS.

  **El frontend no tiene dependencias ni build step** (ADR-0003). La página de verify **verifica
  en el navegador** en vez de mostrar nuestro veredicto: una página que le pregunta a la API
  "¿está bien esto?" y renderiza la respuesta es nuestra opinión con mejor tipografía. `test/web`
  corre el código del navegador contra los **mismos vectores commiteados** que la implementación
  en Go.
- **Fase 9 ✅** — SDKs. `sdk/go` (cliente de los servicios y de `uai-mcp`), `sdk/python`
  (una dependencia: `cryptography`), `sdk/typescript` (cero dependencias, sin build step) y
  `mcp/` con las 8 herramientas de §22.9.

  **El SDK no puede hacer que un agente sea responsable.** Un agente que no quiere serlo no lo
  importa. Lo que hace es que el camino responsable sea el fácil: `with agent.action(...)`
  atestigua **a la salida, siempre** — éxito, excepción y negativa incluidas. Un SDK que
  expusiera `evaluate()` y `attest()` por separado produciría un registro de éxitos, porque los
  caminos de falla son en los que nadie escribe la segunda llamada.

  **Ninguna herramienta MCP otorga capacidades** (§22.9). La regla se sostiene en tres lugares
  que tendrían que fallar juntos: ninguna herramienta la otorga, ninguna ruta de la API la
  otorga, y la base de datos rechaza un grant firmado por el propio agente (migración 0006).
  `tools/uai-grant` es la única vía, y necesita la clave del owner.

  **Tres implementaciones de RFC 8785 y RFC 9421** (ADR-0004). El precio se paga con tests: las
  tres reproducen **los mismos vectores commiteados**, incluido el nuevo
  `attestation/signing-payload.json`.

  Corrió en vivo: registro → bind → passport → acciones desde los tres clientes sobre la misma
  cadena, sin un solo eslabón roto.
- **Fase 10 ✅** — la demo ACME. `make demo` levanta un stack desechable, corre el escenario
  de §24.5 y **falla si alguno de los 21 criterios no queda demostrado**: es un test que se
  puede leer, no una narración que corre.

  **La pieza que faltaba era el pipeline de gobernanza.** `pkg/webauthn` (verificación de
  aserciones, sin dependencias), `pkg/governance` (digest del voto, recuento, prueba de
  gobernanza — funciones puras, sin reloj ni base de datos), el camino
  sospecha → cuarentena → caso → propuesta → votos → decisión → ejecución, y `tools/uai-verify`.

  **El criterio 21 es el test de aceptación real:** `uai-verify` toma un UAI-ID, no busca nada
  que no sea público, y valida la historia entera contra los tres anclajes de §5.1 — incluida
  la revocación, cuyo recuento y prueba **reconstruye desde las aserciones firmadas** en vez de
  leer el resultado que registramos. Si los anclajes se bajan del gateway auditado, lo dice.

  **La demo también muestra lo que el sistema NO hace.** Después de revocar, corre la lógica
  del agente directamente: sigue funcionando. Nada detuvo al código, porque nada en UAI puede.
  Lo único que cambió es que ningún participante honra su identidad — y decirlo en el momento
  más incómodo es la parte más honesta del producto.
- **Fases 11–12 ✅** — seguridad (gates de invariantes, modelo de amenazas validado, pentest)
  y atestación de runtime con SPIRE sobre Podman rootless.
- **Microsprint Federación ✅** — UAI-AS. Cada instalación puede tener número propio
  (`UAI_ASN`), llave propia — distinta de la del emisor — y responder *¿quién es este
  registro?*. Dos registros se configuran mutuamente a mano, se saludan con un `REGISTRY_HELLO`
  firmado, y se pasan un `IDENTITY_ANNOUNCEMENT` sobre una identidad **que el origen emitió**.

  `pkg/federation` (sin dependencias: está en el camino de verificación), migración 0010,
  `internal/api/federation.go`, `tools/uai-federate`, `web/federation.html` y
  `demo/federation.sh` — dos postgres y dos gateways, porque un proceso hablando consigo mismo
  no demuestra nada sobre autonomía.

  **PEER TRUST ≠ AGENT TRUST**, y el esquema lo sostiene: `federated_identities` no tiene clave
  foránea a `agents`, y un CHECK ata cada DID al ASN bajo el que se guarda. Una firma válida no
  es autoridad: un registro puede firmar perfectamente un anuncio sobre el agente de otro, y se
  rechaza con `WRONG_AUTHORITY`.

  El anuncio no tiene ningún campo libre y el decodificador **rechaza miembros desconocidos**.
  Así "no debe contener prompts ni PII" deja de ser una regla de documento.

  **Lo que NO se implementó** está dicho en `docs/Ejemplo_Practico_federation_es.md`:
  REGISTRY_PATH, tránsito, ruteo tipo BGP, confederaciones, descubrimiento automático,
  propagación de cuarentenas o de revocaciones. Las interfaces quedaron extensibles; nada de
  eso existe.

  Primer escritor de `audit_events`, que existía desde la migración 0001 y nadie usaba.

`make integration` levanta Postgres, migra, siembra y corre los tests de store y API con
`-race` más las 86 aserciones de invariantes.

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
16. **Una página que verifica no puede depender de código que no se pueda auditar.** Sin build
    step, lo que se sirve es lo que está en el repo; y cada byte de JS en la página de verify es
    código en el que un visitante confía para saber si confiar en un agente.
17. **Una credencial tiene que valer sin nosotros.** Si validarla exige preguntarle algo a UAI,
    es una respuesta de API con pasos extra, y devuelve el uptime y la honestidad de UAI a la
    ecuación de confianza que el protocolo existe para sacarlas.
18. **Lo que se firma es el documento MENOS su firma, no con la firma en blanco.** §10.4 dice
    "jcs-canonicalize A minus signature". Blanquear un struct deja
    `{"alg":"","domain":"","kid":"","value":""}` en los bytes firmados: cuatro strings vacíos
    que nadie que lea la spec agregaría. Lo encontró el SDK de Python, no una revisión.
19. **Nada que el llamador escriba puede ampliar su propia autorización.** El PDP leía
    `passport` del body: un agente mandaba `{"state":"VALID","allowed_jurisdictions":["KP"]}` y
    un DENY se volvía ALLOW. El passport se lee del registro. `harm_assessment` sí viene del
    body, y es seguro en una sola dirección: solo puede endurecer la respuesta.
20. **Correr el código contra un gateway real encuentra lo que leerlo no.** Las dos fallas
    peores de esta fase (18 y 19) aparecieron en el primer `quickstart.py` en vivo, no en los
    tests que ya estaban en verde.
21. **Una decisión no se cierra antes de que todos hayan hablado.** La propuesta se autorizaba
    con el voto que alcanzaba el umbral y rechazaba a los que faltaban — que en la práctica es
    rechazar la disidencia. El acta mostraba 4-0 donde el consejo votó 4-1. Una decisión cuyo
    registro no puede mostrar quién se opuso es más débil, no más fuerte.
22. **Dos preguntas distintas no comparten una escala.** Para el PDP, DENY es lo más estricto:
    la acción no ocurre. Para el monitor de daño, QUARANTINE es más fuerte que DENY: negar una
    acción es más angosto que restringir al agente. Ordenarlas juntas enterraba
    SAFETY_SYSTEM_BYPASS bajo cualquier otro hallazgo del mismo reporte.
23. **Re-firmar contesta quién aprueba, no cuándo aplica.** `uai-policy sign` traía por defecto
    una fecha de vigencia futura, así que re-firmar tras editar una regla movía en silencio
    cuándo entraba en vigor — y el gateway, fallando cerrado, se negaba a arrancar por un
    cambio que nadie hizo. Ya pasó dos veces; ahora se arrastra del manifest y hay test.
24. **Un gate que nunca se vio fallar no es un gate.** Antes de creerle a uno, romperlo: sacarle
    el trigger a la base, truncarle el archivo, renombrarle el test que cita. Los tres gates de
    la Fase 11 se escribieron así, y dos de ellos no servían hasta que se los rompió.
25. **El exit status de un pipeline es el del último comando.** `psql -f invariants.sql | grep
    PASS | sed ...` imprimía `FAIL INV-003 the forbidden operation SUCCEEDED` en rojo y salía 0.
    La suite de invariantes existió desde la Fase 3, corrió en cada `make integration`, y no
    pudo hacer fallar nada en nueve fases. Ninguna aserción sale por un pipe.
26. **Una suite que puede encoger o cortarse a la mitad en silencio no es un gate.** Contar lo
    que corrió contra lo que el archivo contiene. "Las aserciones que corrieron pasaron" y "toda
    aserción corrió y pasó" son afirmaciones distintas, y solo la segunda sirve.
27. **Un documento que describe controles deriva hacia describir intenciones.** El registro de
    amenazas listaba rate limiting, prueba de dominio `did:web`, notificación al owner, SBOM y
    firma de artefactos, contra-atestación y detección de fork entre instancias. Ninguno existe.
    El preámbulo lo cubría ("después de implementar los controles"); nadie lee una tabla así.
    Ahora cada amenaza declara estado y nombra un archivo, y `make threats` falla si el archivo
    no está o si el test que cita se renombró.
28. **Verificar una firma contra un digest guardado prueba que ese digest se firmó, no que la
    fila alrededor sea cierta.** El recuento verificaba la aserción WebAuthn contra la columna
    `vote_digest` y después informaba la columna `value`, sin que nada revisara que las dos
    fueran juntas. Una aserción genuina del delegado, archivada con el valor opuesto, pasaba
    todas las revisiones de la aplicación. El digest se reconstruye desde el statement — el
    valor incluido — así que cambiarlo rompe la firma. El nonce se guarda porque sin él no se
    puede reconstruir nada, y ese era el motivo real del `_ = statement` que estaba en el código.
29. **Atestación no es emisión, y una columna no es un nivel.** SPIRE aporta la tercera columna
    de §6.8; AL2 pide las tres. Escribí el gate de la Fase 12 como "un agente llega a AL2 porque
    su runtime fue atestiguado" y era falso: los `owners` no tienen ningún campo de verificación,
    así que todo el registro está topeado en AL0. Las tres columnas son conjuntivas y el nivel es
    el mínimo; ahora está dicho en la spec, porque dejarlo implícito invitaba la lectura que deja
    que la atestación de workload sola anuncie una identidad como apta para operaciones de
    negocio.
30. **Un selector que matchea varias entradas emite varios SVIDs.** El workload recibe uno por
    cada entrada que le corresponde, y leer `svid.0.pem` devuelve el que SPIRE contestó primero.
    Mi script lo hacía y habría pasado como "la atestación funciona" mientras bindeaba la
    identidad equivocada. Un agente tiene que elegir el SVID que **lo nombra**.
31. **Cada línea de receta de Make es su propio shell.** Un `exit 0` en un guard termina esa
    línea, no el target: la primera versión de `spire-up` imprimía "ya está corriendo" y
    arrancaba un segundo agente al lado del primero.
32. **`pgrep -f` y `pkill -f` matchean el proceso que los corre.** El patrón está en su propia
    línea de comando. Me maté el shell tres veces seguidas antes de aceptarlo. Para procesos
    propios: el pidfile. Para matar por nombre: `pkill -x`.
33. **El `expires_at` sale del certificado, no de una constante.** El binding guardaba
    `now + SVIDTTL` con SVIDTTL de una hora; un SVID que expira en cinco minutos habría quedado
    registrado como runtime vigente mucho después de que el atestador dejó de responder por él.
34. **Un archivo en disco no es una configuración corriendo.** Un proceso fija su modo al
    arrancar. `deploy.sh status` leía `.spire/gateway/tls.pem` y el pid del agente SPIRE, y
    reportaba "atestación: on" mientras el gateway que estaba sirviendo había arrancado antes que
    el agente y no tenía ninguna. El estado de un servicio se le pregunta al servicio.
35. **Negarse a pisar algo es media compuerta; la otra mitad es el camino hacia adelante.**
    `nuke` borra la base y deja las llaves, y entonces `uai-register owner` se niega
    correctamente y sin salida. Una negativa sin siguiente paso enseña a borrar claves privadas
    para destrabarse, que es exactamente lo que la negativa existía para evitar.
36. **Re-serializar lo recibido es cambiar el documento antes de verificarlo.** El campo
    `timestamp` era un `time.Time`, y el RFC3339Nano de Go borra los ceros finales de los
    decimales: `...04.505890Z` volvía a salir como `...04.50589Z`. Los bytes canónicos de §10.4
    se calculaban entonces sobre un documento que el agente nunca mandó, la firma no daba, y se
    le informaba al agente que su firma era inválida. Como Python emite seis decimales y
    JavaScript tres, una de cada diez acciones se rechazaba al azar culpando al cliente. JCS
    preserva los strings tal cual; canonicalizar lo firmado exige conservar lo escrito.
37. **Una falla intermitente no se bisecta a ojo.** Concluí "es el SDK" con dos corridas de cada
    lado y estaba mal: el bug tenía ~30% por corrida y existía desde antes. Con una falla que no
    es determinista, medir de a dos muestras produce la respuesta que uno ya esperaba.
38. **`UNIQUE (a, b)` no dice nada sobre `b` solo.** `UNIQUE (agent_id, key_id)` impedía que un
    agente tuviera dos filas `key-1` y no impedía que **dos agentes distintos registraran la
    misma llave pública**: dos identidades cuyas firmas son indistinguibles, y una vía para que
    un dueño cuyo agente fue revocado siga operando bajo la segunda. Lo encontré registrando dos
    agentes con una llave y viendo entrar a los dos. Migración 0008; el thumbprint se calcula en
    SQL para que la regla no dependa de que la aplicación se acuerde, y está fijado contra el
    vector de RFC 8037 A.3 y no contra nuestro propio Go.
39. **Una columna GENERATED está vacía dentro de un trigger BEFORE.** Postgres la calcula
    después. Mi primer trigger leía `NEW.thumbprint`, que ahí siempre es NULL, y rechazaba
    **todos** los registros — incluido el primero, legítimo. Una compuerta que rechaza todo se ve
    igual que una que funciona, y solo se distingue probando el caso que debe PASAR.
40. **`uai-migrate down` nunca funcionó.** Buscaba `0008_x.down.sql` en un registro que guarda
    `0008_x.up.sql`, no lo encontraba, decía "never applied" y no hacía nada. Una dirección de
    rollback que no-opea en silencio es peor que una que no existe: se confirma que "el rollback
    corrió" y el esquema sigue igual.
41. **Blanquear la firma no es sacarla, y la regla 18 vuelve en cada objeto firmado nuevo.** El
    handler de peering canonicalizaba un `PeerRequest` con la firma en cero, que serializa cuatro
    strings vacíos que ningún firmante produjo. El cliente firmaba un documento y el servidor
    verificaba otro, así que **todos** los pedidos legítimos daban 401. Lo escribí yo, sabiendo
    la regla, en la primera función del archivo.
42. **`go run` compila a un binario temporal y lo ejecuta como HIJO.** El pid que reporta es el
    del envoltorio: matarlo deja el servicio escuchando. La corrida siguiente encontró el puerto
    contestando, se salteó su propio arranque y habló con el build anterior — que se ve
    exactamente igual que un cambio de código que no tuvo efecto. En scripts: compilar y correr
    el binario.
43. **Una asignación toma el exit status de su sustitución.** `stale=$(... | grep ...)` bajo
    `set -e` termina el script cuando grep no encuentra nada — o sea, en el caso normal. El
    `|| true` va en la asignación, no solo en lo que viene después.
44. **Un id de fixture dentro del rango de un asignador es una compuerta que se erosiona con el
    uso.** `invariants.sql` usaba `UAI-INC-000041` y el asignador reparte `UAI-INC-%06d` contando
    desde uno: la suite empezó a fallar el día que el registro abrió su caso número 41. No fue
    un cambio de código, fue que el sistema se usó.

45. **Un valor derivado no se guarda.** `agents.assurance_level` se escribía una vez en el
    registro y nada la actualizaba nunca; cuatro superficies la leían como si fuera el estado
    actual — incluido el nivel estampado dentro de un credencial de pasaporte **firmado**. Una
    copia guardada de algo derivado es un caché, y ése no tenía ninguna vía de invalidación: la
    evidencia cambia cuando rota una llave, vence un binding o se verifica a un dueño, y ninguno
    de esos eventos pasaba cerca de la columna.

    Coincidían con el valor derivado sólo porque la verificación del dueño está clavada en
    `SELF_ASSERTED` y hoy **todo es AL0**. Eso es lo peligroso: mientras un derivado es constante,
    ningún test de comportamiento distingue "derivado" de "guardado", y el defecto es invisible
    hasta el día que el derivado se mueve. Si no podés escribir un test que falle, la compuerta
    tiene que ser estructural: la columna se borra (0011) y el campo sale del struct, para que
    la lectura vieja sea un error de compilación y no un número equivocado.

46. **Dos lectores de la misma regla son dos respuestas.** La traducción de "attestor guardado"
    a "dimensión de runtime" vivía privada en `internal/api`, así que cualquier otro lector —un
    CLI de operador, un reporte— tenía que reimplementar que `self-declared` no vale nada. Vive
    en `pkg/assurance.FromEvidence`, junto a la tabla que le da sentido.
