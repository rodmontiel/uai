# Ejemplo práctico: darle identidad a un agente de IA, de principio a fin

> *Este documento se corrió entero antes de escribirse. Cada salida que ves abajo es la que
> devolvieron los comandos, no un ejemplo inventado.*
>
> Complementa a [`MANUAL.es.md`](MANUAL.es.md), que explica **qué es** UAI. Esto explica
> **cómo se usa**, paso por paso, con vos en el papel de dueño y un agente de IA en el papel
> de agente.

---

## Lo que vas a construir

Al final de este documento vas a tener:

- **una identidad de dueño** (vos) con una llave privada que vive en tu disco;
- **una identidad de agente** con *otra* llave privada, que el agente usa y vos no tenés;
- **una prueba de dónde corre ese agente**, emitida por SPIRE mirando el proceso, no
  declarada por el propio agente;
- **un permiso que vos otorgaste** con tu llave, y que el sistema hace cumplir;
- **una acción registrada**, firmada, encadenada a las anteriores y con recibo de inclusión
  en un log de transparencia;
- **una verificación completa** que cualquiera puede repetir sin creerle a UAI ni a vos.

🍎 **Con manzanas:** vas a montar el equivalente digital de una ferretería. Vos sos el dueño y
tenés un sello. Contratás a alguien, le das un carnet, y en la puerta hay un guardia que le saca
la foto para confirmar que el que entró es el que dice ser. Le das la llave de **un cajón**, no
del local. Y cada vez que saca algo, firma un remito que queda en un libro donde no se puede
arrancar una hoja sin que se note.

---

## Antes de empezar

Necesitás el stack corriendo. Si no lo tenés:

```bash
cd ~/Grav/uai
./deploy.sh up
```

Al terminar te imprime las tres variables que necesita todo lo demás. **Copialas tal cual** —
cambian según si la atestación está encendida o no:

```
  To register from this shell
    export PG_DSN="postgres://uai:uai@localhost:5432/uai?sslmode=disable"
    export UAI_ENDPOINT="https://localhost:8080"
    export UAI_API_CA=".spire/bootstrap.pem"
```

Pegá esas tres líneas en tu terminal. Si `UAI_ENDPOINT` dice `http://` en vez de `https://`, la
atestación está apagada: el ejemplo funciona igual, pero el paso 3 va a registrar un runtime
*auto-declarado* en lugar de uno atestiguado, y el documento lo aclara cuando llega ahí.

Para encenderla:

```bash
make spire-up && ./deploy.sh up
```

---

## Paso 1 — El dueño sos vos

🍎 **Con manzanas:** el dueño es quien responde si algo sale mal. No es un usuario ni una
cuenta: es una persona o una empresa con un sello que nadie más tiene.

**Lo que pasa de verdad:** se crea una organización, un dueño y una llave Ed25519 que se
escribe en `.keys/owner.jwk` con permisos `0600`. Esa llave nunca sale de tu disco. Crear un
dueño **necesita la base de datos y no la API**, a propósito: una ruta que cualquiera pudiera
llamar haría que "registrado a nombre de un dueño" significara "a nombre de lo que alguien
tipeó".

```bash
go run ./tools/uai-register owner -name "ACME Robotics" -org-did did:web:acme.example
```

**Si ya tenés uno** —el comando se niega a pisar la llave— pedile la lista:

```bash
go run ./tools/uai-register show
```

```
  OWNER                                          ORGANIZATION           AGENTS
  did:uai:owner:01M3KY9S364H567V267AFWSM7F       did:web:acme.example   3  (ACME Robotics)
```

Guardá ese DID: aparece en todos los pasos siguientes. En este documento es
`did:uai:owner:01M3KY9S364H567V267AFWSM7F`; **reemplazalo por el tuyo**.

> Si borraste la base con `./deploy.sh nuke`, las llaves sobrevivieron y el dueño no. No borres
> la llave: volvé a registrarla con `go run ./tools/uai-register owner -reuse-key -name "…"
> -org-did did:web:…`.

---

## Paso 2 — La identidad del agente

🍎 **Con manzanas:** el empleado nuevo trae **su propia** lapicera y vos nunca la tocás. Lo que
lo vuelve tuyo no es que vos se la hayas dado: es que los dos firmaron el mismo papel.

**Lo que pasa de verdad:** el agente genera su llave en tu máquina, y solo la mitad pública
viaja. El registro exige **dos firmas que nombran al mismo sujeto**: la tuya, diciendo "este
agente es mío", y la del agente, diciendo "esta llave es mía". Ninguna sola alcanza. El
identificador no existe hasta que las dos verifican.

```bash
go run ./tools/uai-register agent \
  -owner-did did:uai:owner:01M3KY9S364H567V267AFWSM7F \
  -name "MiPrimerAgente"
```

```
  uai-id     uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  did        did:uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  status     REGISTERED
  key        .keys/miprimeragente.jwk

  It is REGISTERED, not ACTIVE: registration is a claim, and the binding
  that follows it is the proof.
```

**REGISTERED, no ACTIVE.** El registro es una afirmación; falta la prueba. Un agente en este
estado todavía no puede atestiguar nada.

Anotá el `uai-id` y su parte final de 26 caracteres —el **ULID**—, que acá es
`01M3MMR4CN58329M3RXQ9YXETK`.

---

## Paso 3 — Dónde corre, dicho por alguien que no es él

🍎 **Con manzanas:** el guardia de la puerta no te cree el nombre: te saca una foto y emite un
carnet con vencimiento. Si mañana entra otra persona con tu nombre, el carnet no le sirve.

**Lo que pasa de verdad:** SPIRE observa el proceso (acá, por el uid de Unix que lo corre) y le
emite un **X509-SVID**: un certificado cuyo único URI SAN es una identidad SPIFFE. El registro
lee el runtime **del certificado, nunca del cuerpo del pedido**.

El orden no es un detalle: **la entrada de SPIRE nombra al agente**, así que no puede existir
antes de que el agente tenga identificador. Por eso el binding es un paso aparte y no un flag
del registro.

```bash
make spire-entry ULID=01M3MMR4CN58329M3RXQ9YXETK
make spire-svid  ULID=01M3MMR4CN58329M3RXQ9YXETK
```

```
  .spire/svid/svid.6.pem
  URI:spiffe://uai.test/agents/01M3MMR4CN58329M3RXQ9YXETK/i/dev
```

> `spire-svid` con `ULID=` **espera**. El servidor crea la entrada y el agente la aprende en su
> propio intervalo de sincronización, así que un fetch inmediato suele devolver los SVIDs que ya
> tenía y ninguno para la entrada recién creada. Sin la espera, el paso siguiente registra un
> runtime auto-declarado y reporta éxito igual.

Y ahora sí, el binding:

```bash
go run ./tools/uai-register bind \
  -uai-id uai:agent:01M3MMR4CN58329M3RXQ9YXETK \
  -key .keys/miprimeragente.jwk \
  -svid .spire/svid
```

```
  uai-id     uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  status     ACTIVE
  runtime    attested as spiffe://uai.test/agents/01M3MMR4CN58329M3RXQ9YXETK/i/dev
```

**ACTIVE.** Eso ya no lo dijo el agente: lo dice un certificado.

> Si tu stack no tiene atestación, sacá `-svid .spire/svid` y saltá los dos `make`. Vas a llegar
> igual a ACTIVE, pero el runtime va a quedar como `self-declared` — el agente contando dónde
> corre, con nadie chequeándolo. La diferencia se ve en `/verify.html`.

---

## Paso 4 — Miralo en el navegador

Abrí `http://localhost:8081/verify.html` y pegá el UAI-ID.

🍎 **Con manzanas:** es la única pantalla del sistema a la que **no le tenés que creer**. No te
muestra nuestro veredicto: el código que revisa las firmas corre en tu navegador y se puede
leer, son unos cientos de líneas sin librerías externas.

La ficha completa está en `http://localhost:8081/agent.html?id=uai:agent:01M3MMR4CN…`.

---

## Paso 5 — Hablarle al agente: qué es `uai-mcp`

**Acá conviene despejar una confusión.** Claude (o cualquier LLM) **no es** un servidor MCP.
`uai-mcp` es un **programa aparte** que vive en este repo:

```
  Claude Code  ──stdin/stdout──>  uai-mcp  ──https──>  gateway UAI
  (el cliente)                    (tiene la llave      (el registro)
                                   del agente)
```

🍎 **Con manzanas:** `uai-mcp` es el **cajón con la lapicera del empleado**. Claude puede abrir
el cajón y usar la lapicera, pero la lapicera no es Claude: si mañana usás otro programa, la
misma lapicera escribe igual, y la firma sigue siendo la del mismo empleado.

**Lo que pasa de verdad:** `uai-mcp` sostiene `.keys/miprimeragente.jwk`, expone 8 herramientas
por JSON-RPC sobre stdio, y **firma cada llamada** con esa llave. Ningún cliente MCP ve la
llave.

Compilalo una vez:

```bash
go build -o uai-mcp ./mcp
```

### Probarlo sin cablear nada

Para ver las herramientas ahora mismo, sin tocar la configuración de Claude Code, exportá la
identidad y usá el envoltorio:

```bash
export UAI_AGENT_ID="uai:agent:01M3MMR4CN58329M3RXQ9YXETK"
export UAI_AGENT_KEY=".keys/miprimeragente.jwk"
export UAI_OWNER_DID="did:uai:owner:01M3KY9S364H567V267AFWSM7F"

./tools/uai-mcp-call.sh --list
```

```
  uai_verify_identity      Verify a UAI identity
  uai_get_status           Status of the calling agent
  uai_check_policy         Evaluate a policy decision without acting
  uai_attest_action        Attest an action that was performed
  uai_request_capability   Request a capability from the owner
  uai_verify_passport      Check passport scope for a jurisdiction set
  uai_report_incident      File a harm suspicion
  uai_register             Start a registration
```

```bash
./tools/uai-mcp-call.sh uai_get_status
```

```json
{
  "uai_id": "uai:agent:01M3MMR4CN58329M3RXQ9YXETK",
  "logical_name": "MiPrimerAgente",
  "status": "ACTIVE",
  "assurance_level": "UAI-AL0",
  "policy_version": "GASC-2027.4"
}
```

### Conectárselo a Claude Code

```bash
claude mcp add uai -- $PWD/uai-mcp \
  -endpoint https://localhost:8080 \
  -ca $PWD/.spire/bootstrap.pem \
  -uai-id uai:agent:01M3MMR4CN58329M3RXQ9YXETK \
  -key $PWD/.keys/miprimeragente.jwk \
  -owner-did did:uai:owner:01M3KY9S364H567V267AFWSM7F
```

Usá **rutas absolutas**: Claude Code arranca el proceso desde su propio directorio de trabajo.
Después de esto, Claude puede llamar esas 8 herramientas, y **todo lo que haga con ellas queda
firmado con la llave de `MiPrimerAgente`**.

---

## Paso 6 — Pedir permiso antes de actuar

🍎 **Con manzanas:** antes de abrir el cajón, el empleado pregunta si puede. No abre y avisa
después.

**Lo que pasa de verdad:** el guardrail evalúa la política firmada (el bundle `GASC-2027.4`,
firmado 3-de-5) y devuelve una **decisión firmada**, con su identificador y las reglas que se
dispararon. Todavía no otorgaste nada, así que:

```bash
./tools/uai-mcp-call.sh uai_check_policy \
  '{"capability":"docs.read","purpose":"leer el repo para responder","target_jurisdictions":["AR"]}'
```

```json
{
  "decision_id": "01M3MMVHBGZZNMSWQDVSF91P2H",
  "policy": { "version": "GASC-2027.4", "bundle_hash": "sha256:fa51bb4c…" },
  "decision": "DENY",
  "reason": "capability_not_granted",
  "rules_fired": ["gasc.capability.not_granted"]
}
```

**DENY.** Y no es una sugerencia: sin una decisión ALLOW, el paso 10 se niega a registrar la
acción.

---

## Paso 7 — El agente pide la capacidad

🍎 **Con manzanas:** el empleado te deja una nota pidiendo la llave del cajón, explicando para
qué. La nota no es la llave.

**Lo que pasa de verdad:** se crea una solicitud `PENDING`. **Ninguna ruta de la API puede
aprobarla, incluida esta.** Y la base rechaza un otorgamiento firmado por el propio agente: la
regla se sostiene en tres lugares que tendrían que fallar juntos.

```bash
./tools/uai-mcp-call.sh uai_request_capability \
  '{"capability":"docs.read","justification":"Leer documentos del repo para responder preguntas"}'
```

```json
{
  "request_id": "capreq-01M3MMVHCEB75H2NN888G70N1R",
  "capability": "docs.read",
  "state": "PENDING",
  "granted": false,
  "note": "This is a request, not a grant. It creates a pending item for the owner to decide out of band. Nothing in this API can approve it, including this endpoint."
}
```

---

## Paso 8 — Vos decidís, con tu llave

🍎 **Con manzanas:** vos leés la nota y abrís la caja fuerte. El empleado no puede hacer esto
por más que quiera: no tiene el sello.

**Lo que pasa de verdad:** `uai-grant` **no es parte de la API**, a propósito. Cada comando
necesita la llave privada del dueño, que el proceso del agente no tiene y nunca debe tener.

```bash
go run ./tools/uai-grant list -owner did:uai:owner:01M3KY9S364H567V267AFWSM7F
```

```
capreq-01M3MMVHCEB75H2NN888G70N1R
  agent      uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  owner      did:uai:owner:01M3KY9S364H567V267AFWSM7F
  capability docs.read
  because    Leer documentos del repo para responder preguntas
  asked      2026-09-28T18:36:23Z (expires 2026-10-28T18:36:23Z)
```

```bash
go run ./tools/uai-grant approve \
  -request capreq-01M3MMVHCEB75H2NN888G70N1R \
  -key .keys/owner.jwk \
  -owner did:uai:owner:01M3KY9S364H567V267AFWSM7F
```

```
APPROVED docs.read for uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  expires 2026-12-27T18:36:32Z
  signed by did:uai:owner:01M3KY9S364H567V267AFWSM7F#key-1
```

Para negarla, `uai-grant deny` con los mismos argumentos y un `-note` opcional.

---

## Paso 9 — Ahora sí

```bash
./tools/uai-mcp-call.sh uai_check_policy \
  '{"capability":"docs.read","purpose":"leer el repo para responder","target_jurisdictions":["AR"]}'
```

```json
{
  "decision": "ALLOW",
  "reason": "baseline_allow",
  "rules_fired": ["gasc.baseline.allow"]
}
```

---

## Paso 10 — El techo: lo que vos NO podés otorgar

Esta es la parte que más cuesta ver y la que más importa.

🍎 **Con manzanas:** te identificaste con una fotocopia del documento. El dueño puede
autorizarte por escrito a retirar plata del banco, y el banco te va a decir que no igual — no
por desconfiar del dueño, sino porque **con una fotocopia no se retira plata**.

**Lo que pasa de verdad:** cada capacidad declara un piso de garantía. `docs.read` pide
**UAI-AL0**; `crm.customer.read` pide **UAI-AL1**. El nivel de una identidad es el **mínimo**
de tres dimensiones (protección de la llave, verificación del dueño, atestación del runtime), y
tu agente está en AL0 porque **nadie demostró control del DID de tu organización**.

Probalo: pedí `crm.customer.read`, aprobala con tu llave, y consultá igual.

```bash
./tools/uai-mcp-call.sh uai_request_capability \
  '{"capability":"crm.customer.read","justification":"ver hasta donde llega mi nivel"}'
# → capreq-…

go run ./tools/uai-grant approve -request capreq-… \
  -key .keys/owner.jwk -owner did:uai:owner:01M3KY9S364H567V267AFWSM7F
# → APPROVED crm.customer.read

./tools/uai-mcp-call.sh uai_check_policy \
  '{"capability":"crm.customer.read","purpose":"leer clientes","target_jurisdictions":["AR"]}'
```

```json
{
  "decision": "DENY",
  "reason": "assurance_below_floor",
  "rules_fired": ["gasc.capability.assurance_floor"]
}
```

**Tu firma no compra nivel de garantía.** Podés autorizar todo lo que quieras; el piso lo pone
la política, no vos. Las capacidades y sus pisos están en la tabla `capabilities`:

```bash
podman exec uai_postgres_1 psql -U uai -d uai -c \
  "SELECT name, risk, min_assurance FROM capabilities ORDER BY min_assurance, name"
```

---

## Paso 11 — La acción, atestiguada

🍎 **Con manzanas:** el empleado saca algo del cajón y firma el remito. El remito lleva el
número del remito anterior, así que no se puede intercalar ni arrancar uno sin que la
numeración deje de cerrar.

**Lo que pasa de verdad:** se evalúa la política, se firma la atestación en el dominio
`UAI-v1:attestation`, y se agrega a la cadena de hashes del agente. Del contenido solo viaja un
**compromiso con sal**: el texto de `input_summary` y `output_summary` nunca sale del proceso,
y las sales vuelven a vos para que puedas demostrar después qué había.

```bash
./tools/uai-mcp-call.sh uai_attest_action '{
  "capability":"docs.read",
  "purpose":"explicar que hace pkg/attest",
  "resource":"pkg/attest/attest.go",
  "outcome":"SUCCESS",
  "origin":"AR", "targets":["AR"], "basis":"resource_location",
  "risk_class":"LOW",
  "input_summary":"pregunta sobre el paquete attest",
  "output_summary":"explicacion del formato"
}'
```

```json
{
  "decision": "ALLOW",
  "event_id": "evt-584bf29d59f193d45ee0523b71c33111",
  "event_hash": "sha256:c9255c99121a67f3…",
  "input_salt_hex": "f8c069c5a3cd54dd…",
  "output_salt_hex": "a3c30b2a373d4120…",
  "outcome": "SUCCESS",
  "receipt": {
    "log_origin": "uai.world/log/1",
    "log_index": 6,
    "checkpoint": { "size": 7, "root": "cXPZIYnWNAevwDr7Jiussd6WEZJz4G2lq4rFZOLeFc0=" },
    "inclusion_proof": [ "…" ]
  }
}
```

`outcome` acepta `SUCCESS`, `FAILURE` y `PARTIAL`. **Atestiguá también los fracasos:** un
registro que solo contiene éxitos es publicidad.

Abrí `http://localhost:8081/explorer.html` y vas a ver el evento con su prueba de inclusión.

---

## Paso 12 — Verificar sin creerle a nadie

🍎 **Con manzanas:** un auditor externo agarra el libro de actas, verifica las firmas contra las
firmas públicas conocidas, y rehace la numeración él mismo. No pregunta si está bien: lo
calcula.

**Lo que pasa de verdad:** `uai-verify` toma un UAI-ID, no busca nada que no sea público, y
**recalcula** el veredicto del registro en vez de imprimirlo.

```bash
go run ./tools/uai-verify -v uai:agent:01M3MMR4CN58329M3RXQ9YXETK \
  -endpoint https://localhost:8080 -ca .spire/bootstrap.pem
```

```
uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  did     did:uai:agent:01M3MMR4CN58329M3RXQ9YXETK
  status  ACTIVE
  events  1
  anchors FETCHED FROM THE GATEWAY BEING AUDITED — pin them with -anchors

  ok  did document resolves keys                   1 verification method(s), with validity windows
  ok  chain links unbroken                         1 events, every one naming its predecessor
  ok  checkpoint signed by the log key             size 7, root sha256:7173d92189d63407…
  ok  checkpoint co-signed by witnesses            2 of 2 required
  ok  attestation signatures                       1 verified against the key valid at signing time
  ok  transparency receipts                        1 inclusion proof(s) rebuilt the signed root
  --  revocation follows from signed votes         this identity is ACTIVE
  ok  the registry's verdict matches the record    UAI_VERIFIED, recomputed rather than taken on trust

7 checks passed, 1 not applicable
```

Fijate en la línea de los anclajes: los bajó **del gateway que está auditando**, y lo dice. En
serio se hace con `-anchors anclajes.json` apuntando a un archivo que conseguiste por otro lado.

---

## Lo que esto NO hace

La última línea de `uai-verify` lo dice mejor que cualquier resumen:

> *Esto dice que el registro es internamente consistente y está firmado por las llaves que
> nombra — no que las acciones descritas hayan tenido los efectos que dicen.*

Tres límites, dichos derecho:

**Nada intercepta.** UAI no tiene gancho al kernel, ni shim, ni plugin de sshd. Si el agente
abre una conexión SSH y no lo atestigua, no queda registrado. Lo que no puede es **negarlo
después**, ni atestiguar en nombre de otro, ni que su registro tenga solo éxitos.

**Una atestación es una afirmación, no una prueba del efecto.** Probar que el banco movió la
plata requiere que el banco contra-atestigüe. Eso es §10.8, opcional, y todavía no está
implementado.

**Revocar no apaga nada.** Si revocás esa identidad, el proceso sigue corriendo igual. Lo único
que cambia es que ningún participante que verifique la honra. No hay interruptor global, y
cualquier texto que insinúe lo contrario es un bug.

---

## Empezar de cero

`./deploy.sh nuke` borra la base. **Las llaves no**, y eso es a propósito: una llave privada
borrada no se recupera, y el mismo archivo puede seguir nombrando a un dueño en otra base que
este script no conoce.

Así que después de un `nuke` tenés dos caminos, y ninguno es "borrá `.keys/` a mano":

**Quedarte con las llaves** — son tuyas, lo que se perdió es el registro:

```bash
go run ./tools/uai-register owner -reuse-key -name "ACME Robotics" -org-did did:web:acme.example
go run ./tools/uai-register agent -owner-did did:uai:owner:... -name "MiPrimerAgente" -reuse-key
```

**O empezar realmente limpio**, con las llaves incluidas. Es explícito y te dice qué borra:

```bash
./deploy.sh nuke --keys
```

🍎 **Con manzanas:** `nuke` tira los papeles de la ferretería. Las llaves físicas siguen en tu
bolsillo — sirven, pero ya no hay registro de a qué cajón abren. Podés volver a anotarlas
(`-reuse-key`) o tirarlas también (`--keys`). Lo que el script no hace es tirártelas sin
preguntar.

> **Una llave, una identidad.** Si intentás registrar dos agentes con la misma llave, el
> registro lo rechaza con `UAI_KEY_NOT_UNIQUE`. No es una regla de estilo: dos identidades con
> una llave hacen que una firma ya no diga cuál de las dos hizo la afirmación, y que revocar
> una deje a la otra operando con la misma llave.

---

## Si algo falla

| Síntoma | Causa y solución |
|---|---|
| `Client sent an HTTP request to an HTTPS server` | El gateway sirve TLS y tu `-endpoint` dice http. Agregá `-endpoint https://localhost:8080 -ca .spire/bootstrap.pem`, o exportá las variables que imprime `./deploy.sh up` |
| `certificate signed by unknown authority` | Falta el CA. `-ca .spire/bootstrap.pem`, o `export UAI_API_CA=.spire/bootstrap.pem` |
| `uai-verify` imprime el uso y sale 2 | Se pasaron dos identificadores, o ninguno. El mensaje dice cuántos recibió |
| `UAI_RUNTIME_ATTESTATION_REQUIRED` en el bind | Tu stack verifica runtimes, así que el bind necesita presentar un SVID: `make spire-entry ULID=… && make spire-svid ULID=…` y después `bind -svid .spire/svid` |
| `no SVID naming <ULID> after 20s` | No hay entrada para ese ULID. Corré `make spire-entry ULID=…` primero |
| `UAI_OWNER_NOT_ELIGIBLE` | El dueño que nombraste no está en esta base. `go run ./tools/uai-register show` lista los que hay |
| `.keys/owner.jwk already exists` | Está bien, no la va a pisar. Si el dueño existe, el mensaje te dice cuál es; si no existe ninguno, `uai-register owner -reuse-key` |
| `UAI_KEY_NOT_UNIQUE` | Esa llave ya nombra a otra identidad. Una llave nombra a una sola: dos identidades compartiéndola hacen que una firma no diga cuál de las dos firmó. Generá una nueva, o usá la identidad que ya existe |
| `.keys/<agente>.jwk already exists` | No la va a pisar: esa llave **es** una identidad. Si todavía nombra a una viva, usá esa (`uai-register show`). Si su base se borró, `-reuse-key` |
| Querés una prueba limpia sin datos | `./deploy.sh nuke` borra la base y deja las llaves; `./deploy.sh nuke --keys` borra también las llaves, nombrando cada archivo |
| `capability_not_granted` | Nadie te otorgó esa capacidad. Pedila y aprobala (pasos 7 y 8) |
| `assurance_below_floor` | La capacidad pide más nivel del que la identidad tiene. Ver el paso 10 |
| `Command 'go' not found` | Go no está en el PATH. `export PATH="$PATH:$HOME/.local/go/bin"`. `make check-go` dice qué toolchain va a usar la build |

---

## Para seguir

- [`MANUAL.es.md`](MANUAL.es.md) — qué es cada pieza y por qué existe
- `make walkthrough` — los 21 criterios del escenario completo, de a uno, sobre este mismo stack
- [`protocol/`](protocol/) — la especificación normativa, 26 secciones (en inglés)
