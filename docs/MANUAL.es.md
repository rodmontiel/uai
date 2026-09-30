# Manual técnico

> *También disponible en inglés: [`MANUAL.md`](MANUAL.md).*
>
> Referencia de los componentes de UAI: qué estándar implementa cada uno, qué garantiza, dónde
> vive en el repositorio y cómo falla. Para el recorrido paso a paso con comandos y salidas
> reales, ver [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md).

---

## 1. El problema

Un agente autónomo ejecuta una acción. **¿Quién la ejecutó, y quién responde por ella?**

El rastro habitual es una línea de log emitida por el mismo proceso que actuó, sin firma, sin
referencia a la política vigente al momento de decidir, y sin forma de detectar que fue editada
después. No es evidencia: es una afirmación no verificable del propio interesado.

UAI produce, para cada acción, un registro firmado que nombra la identidad, su dueño declarado,
la capacidad ejercida, el propósito, la versión exacta del reglamento que la autorizó y el
resultado — encadenado al registro anterior y verificable por un tercero sin ejecutar código de
este repositorio.

### Límites declarados

- **UAI no evalúa si un agente es seguro.** Establece atribución, no inocuidad.
- **UAI no tiene un interruptor global de apagado.** Revocar una identidad significa que los
  participantes dejan de honrar sus credenciales. El proceso no se detiene: un agente en una
  máquina desconectada sigue corriendo. `make demo` lo demuestra explícitamente.
- **Una atestación prueba que se afirmó una acción, no que sus efectos ocurrieron.** Probar el
  efecto requiere que el sistema destino contra-atestigüe, y eso no está implementado.

---

## 2. Los cuatro artefactos

| Artefacto | Estándar | Forma en el cable | Responde |
|---|---|---|---|
| **UAI-ID** | ULID + W3C DID | `uai:agent:01M3QA6…` ↔ `did:uai:agent:01M3QA6…` | *¿quién es?* |
| **UAI Credential** | W3C VC 2.0 + Data Integrity | `AgentIdentityCredential`, `AgentOwnershipCredential` | *¿quién responde, y qué se le habilitó?* |
| **UAI Passport** | W3C VC 2.0 | `AgentPassportCredential`, con `validUntil` | *¿dónde, y hasta cuándo?* |
| **Action Attestation** | JSON firmado, encadenado por hash | `uai_version`, `sequence`, `previous_event_hash` | *¿qué hizo?* |

El identificador es un ULID: 26 caracteres en Crockford base32, ordenable por tiempo, generado sin
coordinación central. El DID se deriva de él 1:1, de modo que un verificador que resuelve el DID y
uno que consulta el UAI-ID hablan de la misma entidad sin tabla de traducción.

**Credencial y pasaporte no son intercambiables.** La credencial otorga la capacidad
(`crm.customer.read`) y sólo la firma el dueño. El pasaporte acota jurisdicción y vigencia
(`AR, DE`, hasta `2027-03-21`) y **no puede agregar una capacidad que el dueño no otorgó**. Por eso
un agente puede pedir su propio pasaporte sin que eso constituya un auto-permiso: el peor caso de
un pasaporte fraudulento es acotar más, nunca ampliar.

Cada capacidad declara además un **piso de garantía** (`min_assurance`). Un pasaporte que liste
`cloud.securitygroup.update` con piso `UAI-AL3` sobre una identidad en `UAI-AL0` no habilita nada:
el guardarraíl rechaza la acción con `assurance_below_floor` y nombra la regla que disparó.

---

## 3. Componentes

### 3.1 Firma — Ed25519

Claves Ed25519 (RFC 8032). La privada nunca sale del proceso que la posee; en este repositorio
vive en `.keys/`, que está en `.gitignore` y nunca se commitea.

Lo que se firma es **el documento canonicalizado menos el miembro de la firma**. El miembro se
**quita**, no se blanquea: una implementación que lo blanqueara estaría firmando cuatro strings
vacíos que ningún otro firmante agrega, y sus documentos verificarían sólo contra sí misma.

Las claves se resuelven **como eran válidas al momento del evento**, no como son ahora
(`pkg/keys`). Una firma hecha antes de que su clave fuera revocada sigue verificando; una hecha
después, no. Sin esa regla, rotar una clave invalidaría retroactivamente toda la historia, y
declarar un compromiso no invalidaría nada.

### 3.2 Canonicalización — JCS, RFC 8785

`{"a":1,"b":2}` y `{ "b":2, "a":1 }` son el mismo objeto y bytes distintos, así que producen
firmas distintas. JCS fija el orden de los miembros, la codificación de los números y el escapado
de las cadenas, de modo que dos implementaciones produzcan byte por byte lo mismo.

Implementado **tres veces** en este repositorio — Go, Python, TypeScript — y las tres se prueban
contra los mismos vectores en `spec/test-vectors/jcs/`. Los vectores se leen, nunca se regeneran
en los tests: `make vectors-check` falla si regenerarlos cambiaría algo. Sin eso, tres
implementaciones se convierten en tres protocolos.

### 3.3 Separación de dominios

Lo que se hashea o firma no es el payload sino `DOMINIO || 0x00 || payload`. Los dominios son
constantes con prefijo `UAI-v1:` — `attestation`, `credential`, `vote`, `quarantine`,
`revocation`, `checkpoint`, `commitment`, `passport`, `federation-hello`, y diez más en
`pkg/uaicrypto/digest.go`.

Sin separación, una firma producida para reportar una sospecha (`UAI-v1:suspicion`) podría
presentarse como la orden de cuarentena que viene después (`UAI-v1:quarantine`), porque el payload
nombra al mismo sujeto. Reutilizar un dominio existente para un propósito nuevo es un bug de
seguridad, no un atajo.

### 3.4 Cadena de eventos

Cada evento de un agente —registro, bind, unbind, rebind, acción— lleva el hash del evento
anterior y un `sequence` monótono. El hash cubre el evento **firmado**, no sólo su payload, así
que la cadena ata la firma y no únicamente el contenido.

Un hueco en la numeración o un enlace colgante son visibles para cualquiera que recorra la
historia. Y una cadena **bifurcada** —dos eventos distintos declarando el mismo predecesor— no
tiene explicación inocente: es la señal de que la identidad corre en dos lugares a la vez.

### 3.5 Registro de transparencia — Merkle, RFC 6962

Cada atestación se inscribe en un árbol de Merkle y devuelve un **recibo**: índice de la hoja,
prueba de inclusión, checkpoint firmado y co-firmas de testigos. Un tercero con el statement, el
recibo y las anclas verifica todo sin consultar a nadie.

El log guarda **hashes de hoja, nunca statements**. Un log que acumulara contenido sería lo único
que vale la pena atacar, y su retención dejaría de ser barata y lícita en cuanto guardara algo
sobre una persona.

### 3.6 Testigos

El árbol no detecta **vista partida**: un operador puede mostrar dos historias consistentes a dos
verificadores distintos. La defensa no es criptográfica sino organizativa.

Un testigo co-firma un checkpoint sólo después de comprobar que **extiende** el que ya firmó. Para
sostener dos historias, el operador necesitaría firmas de testigo para dos checkpoints
inconsistentes, y un testigo honesto no puede producir la segunda.

> Hoy los dos testigos corren en la misma máquina. Eso provee **el mecanismo pero no la
> independencia**: la detección de vista partida descansa en que los testigos sean operados por
> partes que no coludirían con el log, y dos procesos en un host no lo son. Declarado, no
> disimulado.

### 3.7 Anclaje en cadena

Periódicamente, la raíz del checkpoint se publica en un ledger de consorcio (`uai-ledger-writer`,
proceso separado del gateway: anclar es durabilidad, no una compuerta de admisión; el gateway debe
seguir aceptando atestaciones con el ledger caído).

**En la cadena no va contenido, sólo compromisos con sal.** `test/onchain` lee los ABIs commiteados
y rechaza cualquier parámetro que no sea `bytes32`, `uintN`, `intN`, `bool`, `address` o una tupla
de ésos. Un `string` o un `bytes` dinámico podría llevar un prompt o un email, y la única forma
confiable de mantenerlos fuera es hacerlos **impronunciables** — por eso INV-007/008 es una
compuerta de build y no un hábito de code review.

La sal es obligatoria y son 32 bytes de `crypto/rand`, uno fresco por compromiso. El hash pelado de
un contenido de baja entropía —un email, un monto, un sí/no— se recupera por diccionario, y un
compromiso publicado en cadena es un error de privacidad permanente. La sal queda con el dueño:
UAI no la tiene y nunca la va a tener, lo que significa que un compromiso cuya sal se perdió no se
puede abrir jamás.

El adaptador público de anclaje se distribuye como `noop-dev`, que **devuelve error en vez de un
hash de transacción plausible**. Un build de desarrollo que inventara un ancla haría que los
recibos afirmaran una durabilidad que nadie proveyó.

### 3.8 Guardarraíl — OPA / Rego

Antes de actuar, el agente consulta al PDP, que evalúa un **bundle de políticas firmado**
(`policy/gasc-2027.4/`). El bundle se commitea con su manifiesto y sus firmas; las claves privadas
de aprobación, no. Editar una regla o un umbral rompe el arranque hasta que alguien con las claves
de gobernanza vuelva a firmar: la política no la cambia quien tiene acceso de escritura al árbol
de fuentes.

**Verificar un bundle y evaluarlo son cosas separadas a propósito.** Evaluar cuesta 33 módulos de
terceros y vive sólo en el PDP; verificar —manifiesto, hash, firmas M-de-N, cadena de versiones—
no tiene dependencias, porque **auditar una decisión pasada nunca debe requerir la maquinaria que
la tomó** ([ADR-0002](adr/0002-opa-embedded-in-the-pdp.md)).

Se registra **toda** decisión, incluidas las `ALLOW`, y cada registro nombra la versión y el hash
exacto del bundle. Un guardarraíl que sólo loguea negativas no puede responder *"¿qué se permitió,
y por qué?"*, que es la pregunta que importa después de un incidente.

### 3.9 Gobernanza — WebAuthn

Revocar una identidad de forma permanente requiere **4 votos de 5 delegados, de al menos 3
jurisdicciones distintas**.

El detalle de diseño central: **el challenge que firma la llave física ES el digest del voto**. No
es autenticarse y después votar; el autenticador firma exactamente el contenido que se está
votando, con `userVerification` requerido.

Consecuencia: **ningún proceso automático puede votar.** Puede poseer la credencial del delegado y
aun así no producir un voto válido, porque el autenticador exige la presencia verificada de una
persona. El registro lo rechaza con `UAI_VOTE_NOT_USER_VERIFIED`.

El administrador es de sólo lectura por construcción. Lo único que puede hacer con una revocación
es **ejecutar** una ya decidida, y `UAIRevocationRegistry.executeRevocation` vuelve a verificar
las firmas de los delegados y el quórum contra `UAIPolicyRegistry` antes de aceptarla. Un
administrador comprometido no revoca a nadie. El quórum no es una constante del contrato: se lee
de la política, así que la gobernanza lo cambia firmando, no redesplegando el código que lo aplica.

### 3.10 Atestación de runtime — SPIFFE/SPIRE

Un binding auto-declarado es el agente afirmando dónde corre, firmado por el agente. Vale lo mismo
que nada, y el sistema lo registra como `self-declared` para que se distinga.

SPIRE observa el proceso desde afuera —selectores del sistema operativo, hoy `unix:uid:N`— y emite
un **X509-SVID**: un certificado cuyo único URI SAN es una identidad SPIFFE. El registro lee el
runtime **del certificado, nunca del cuerpo del pedido**, y comprueba que el SVID nombre a *esa*
identidad: un certificado perfectamente válido de otro agente se rechaza con
`UAI_RUNTIME_IDENTITY_MISMATCH`.

El binding **vence con el SVID que lo probó** (`expires_at` es el `NotAfter` del certificado, no
una constante), y la evidencia vencida no cuenta. La dimensión de runtime no es un logro
permanente: es un estado vivo que hay que renovar.

> **Lo que todavía no se registra:** `runtime_identities.selectors` existe y siempre está vacío. El
> registro guarda el ID SPIFFE que el atestador emitió —un **nombre**— y no la evidencia detrás,
> así que nada distingue una identidad atestada por `unix:uid` (cualquier proceso de ese usuario)
> de una atestada por digest de imagen. Está en
> [§20.5](protocol/13-threat-model.md) con su consecuencia.

### 3.11 Nivel de garantía

El nivel de una identidad (`UAI-AL0`…`UAI-AL3`) es el **mínimo** de tres dimensiones:

| Dimensión | AL1 | AL2 | AL3 |
|---|---|---|---|
| Protección de la llave | software | TPM2, enclave seguro, KMS, WebAuthn | HSM |
| Verificación del dueño | control de dominio | credencial de organización verificada | entidad legal verificada |
| Atestación de runtime | SVID atestado | SVID + digest de imagen del atestador | atestación remota del entorno |

Se **deriva de la evidencia en cada lectura**, nunca se guarda: una copia almacenada sería un caché
sin vía de invalidación, y la evidencia cambia cuando rota una llave, vence un binding o se
verifica un dueño. El registro además dice **qué dimensión es el techo**, porque un `UAI-AL0` a
secas es indistinguible de una mala configuración.

> Hoy la verificación del dueño está clavada en `SELF_ASSERTED`: nada en el esquema registra
> control de dominio. Por eso **toda identidad está en AL0**, incluso una con llave en HSM y
> runtime atestado. La prueba de control de `did:web` figura como faltante en §20.5.

### 3.12 SDK

Tres SDKs (Go, Python, TypeScript) y un servidor MCP con las 8 herramientas de §22.9.

El diseño parte de una limitación que no se puede sortear: **un SDK no puede obligar a un agente a
rendir cuentas**, porque corre dentro del agente. Lo único disponible es hacer que el camino
honesto sea el más corto:

```python
with agent.action("enviar cotización al cliente") as act:
    resultado = hacer_el_trabajo()
```

Consultar la política, atestar el resultado y firmarlo ocurre solo, **incluso si el trabajo lanza
una excepción**: se atesta `FAILURE` y se re-lanza. Un diseño donde hubiera que llamar a un método
al final sería un diseño donde las acciones que salen mal no quedan registradas — y un registro de
accountability que sólo contiene éxitos es publicidad.

Ninguna herramienta MCP otorga capacidades. `uai_request_capability` abre un pedido que **el dueño**
aprueba fuera de banda; el agente no puede aprobarse nada a sí mismo.

### 3.13 Federación — UAI-AS

Una instalación con número propio (`UAI_ASN`) es un **UAI-AS**: tiene DID de registro
(`did:uai-registry:1001`), llave propia distinta de la del emisor, y responde *¿quién es este
registro?*.

Dos registros se configuran mutuamente **a mano**, se saludan con un `REGISTRY_HELLO` firmado, y se
pasan un `IDENTITY_ANNOUNCEMENT` sobre una identidad **que el origen emitió**.

> **PEER TRUST ≠ AGENT TRUST.** Configurar un par significa *"este registro puede mandarme
> statements firmados"*. Nunca significa *"confío en sus agentes"*.

Sostenido por el esquema, no por un comentario: `federated_identities` no tiene clave foránea a
`agents`, y un CHECK ata cada DID al ASN bajo el que se guarda. Una firma válida no es autoridad —
un registro puede firmar perfectamente un anuncio sobre el agente de otro, y se rechaza con
`WRONG_AUTHORITY`.

El anuncio tiene siete campos, ninguno libre, y el decodificador **rechaza miembros desconocidos**.
Así *"no debe contener prompts ni PII"* deja de ser una regla de documento.

Lo que **no** existe —tránsito, `REGISTRY_PATH`, ruteo, descubrimiento automático, propagación de
revocaciones, federación de pasaportes— está enumerado en
[`Ejemplo_Practico_federation_es.md`](Ejemplo_Practico_federation_es.md). La federación es opt-in
y viene apagada: una instalación sin número responde `404 UAI_FEDERATION_NOT_CONFIGURED`.
## 4. Cómo lo pruebo

### Lo que hace falta tener instalado

- **Podman** (o Docker) — para levantar la base de datos y SPIRE en contenedores.
- **Go 1.27** — para compilar.
- **Python 3** con la librería `cryptography` — para la demo y el SDK.
- **psql** — el cliente de PostgreSQL.

> Si Go está instalado pero la terminal te dice `Command 'go' not found`, es que no está en tu
> PATH. Una instalación común lo deja en `~/.local/go/bin`. Lo agregás para esta sesión con
> `export PATH="$PATH:$HOME/.local/go/bin"`, o para siempre poniendo esa línea en `~/.bashrc`.
> Los targets de `make` y `./deploy.sh` lo encuentran solos; esto hace falta únicamente para los
> comandos que escribís vos.

> Un contenedor es un programa empaquetado con todo lo que necesita, que corre aislado del resto de
> la máquina. *Rootless* quiere decir que corre sin permisos de administrador: si algo sale mal,
> el daño está acotado.

### El camino más corto: una sola orden

```bash
make demo
```

Esto levanta todo desde cero, corre el escenario completo de una empresa ficticia, y **falla si
alguno de los 21 criterios del MVP no queda demostrado**. Al final limpia todo lo que creó.

No es una narración: es un test que se puede leer. Muestra registrar un agente, atarlo a un
runtime, pedir permisos, actuar, que el guardarraíl deniegue algo, abrir un caso, votar una
revocación con cinco delegados, ejecutarla, y verificar todo desde afuera.

Termina así:

```
21/21 criteria demonstrated
```

### Levantar la plataforma para usarla

Una sola orden, todo en contenedores:

```bash
./deploy.sh up
```

La primera vez construye las imágenes y tarda unos minutos; después son unos 8 segundos. Al
terminar te muestra qué levantó y en qué puertos.

```bash
./deploy.sh up       # construir lo que falte, levantar todo, aplicar el esquema
./deploy.sh down     # apagar, conservando los datos
./deploy.sh nuke     # apagar y borrar los datos (--keys: también las llaves)
./deploy.sh status   # qué está corriendo y en qué puertos
./deploy.sh env      # los exports que leen las herramientas: eval "$(./deploy.sh env)"
./deploy.sh logs uai-gateway   # seguir los registros de un servicio
```

Y después, en el navegador: **http://localhost:8081**

Con `podman ps` vas a ver cuatro contenedores:

```
uai_postgres_1       la base de datos
uai_spire-server_1   la autoridad que certifica dónde corre cada agente
uai_uai-gateway_1    la API
uai_uai-web_1        la interfaz web
```

> **Lo único que no es un contenedor es el agente de SPIRE**, y no es un descuido. Ese componente
> identifica a un proceso mirándolo desde afuera, así que tiene que compartir la misma vista que
> los procesos que certifica — y los agentes que vas a querer certificar corren en tu máquina, no
> dentro de este stack. Se enciende con `make spire-up`, y `./deploy.sh status` te dice si está.

### Si preferís trabajar sobre el código

Para desarrollar conviene correr la API desde las fuentes en vez de desde una imagen:

```bash
make dev          # solo la infraestructura (base de datos + SPIRE)
make run-gateway  # la API, desde el código
make run-web      # la interfaz, desde el código
```

La diferencia: `./deploy.sh up` corre lo que está construido, `make dev` + `make run-*` corre lo
que estás editando.

### Registrar tu primer agente

Una identidad no es algo que UAI reparta. Se crea con **dos firmas que nombran al mismo sujeto**:
la del dueño, diciendo "este agente es mío", y la del propio agente, diciendo "esta llave es mía".
Ninguna de las dos sola prueba nada, y por eso no hay un botón para esto.

`uai-register` hace ese intercambio.

**Paso 1 — crear un dueño.** El dueño es quien responde por el agente. Crearlo necesita la base de
datos y no la API, y eso es a propósito: una ruta que pudiera llamar cualquiera haría que
"registrado a nombre de un dueño" significara "registrado a nombre de lo que alguien tipeó".

Definí las dos direcciones una sola vez. `owner` y `show` van directo a la base; `agent` y `bind`
pasan por el gateway, y toman esto sin que haya que decírselo:

```bash
export PG_DSN="postgres://uai:uai@localhost:5432/uai?sslmode=disable"
export UAI_ENDPOINT="https://localhost:8080"
export UAI_API_CA=".spire/bootstrap.pem"
```

Las dos últimas son para un stack **con atestación**, que sirve TLS: un SVID es un certificado de
cliente, y en una conexión plana no hay dónde ponerlo. `.spire/bootstrap.pem` es la raíz de
confianza que emitió el SPIRE que está corriendo — la misma contra la que el gateway verifica a los
clientes, así que las dos direcciones confían en una sola raíz. Con la atestación apagada el gateway
sirve HTTP plano: usá `http://127.0.0.1:8080` y `unset UAI_API_CA`. `./deploy.sh up` imprime el par
correcto para el stack que acaba de levantar, y `./deploy.sh status` dice en cuál estás.

```bash
go run ./tools/uai-register owner -name "ACME Robotics" -org-did did:web:acme.example
```

```
  organization  did:web:acme.example
  owner         did:uai:owner:01M3D4QCXVCDNFT1GATPY98FDW
  key           .keys/owner.jwk
```

Esa llave firma por todos los agentes que cuelguen de ella. Es el único archivo acá cuya pérdida
no se arregla volviendo a correr nada.

El comando se niega a pisar un `.keys/owner.jwk` que ya existe, y después de `./deploy.sh nuke` esa
negativa es con lo que uno choca: la base ya no está, la llave en disco sí. La llave sigue siendo
tuya — lo que se perdió es el registro. Volvé a registrarla en lugar de borrarla:

```bash
go run ./tools/uai-register owner -reuse-key -name "ACME Robotics" -org-did did:web:acme.example
```

El dueño recibe un identificador nuevo, porque el anterior existía únicamente en la base que se
borró. `-reuse-key` igual se niega si algún dueño de *esta* base ya usa esa llave: una llave detrás
de dos dueños es una firma que ya no dice cuál de los dos hizo la afirmación.

**Paso 2 — registrar el agente.** Su llave se genera en tu máquina y nunca sale de ahí; solo viaja
la mitad pública.

```bash
go run ./tools/uai-register agent -owner-did did:uai:owner:01M3D4QCXV… -name "RoutePlanner"
```

```
  uai-id     uai:agent:01M3D51K666A82R8VRG7EAC1PB
  status     REGISTERED
  key        .keys/routeplanner.jwk
```

**REGISTERED, no ACTIVE.** Registrarse es una afirmación; el binding que viene después es la
prueba. Un agente en ese estado todavía no puede atestar acciones.

**Paso 3 — atar un runtime.** Es lo que dice *dónde* corre el agente, y lo lleva a ACTIVE.

```bash
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk
```

Si tu stack tiene SPIRE encendido, ese comando se rechaza — y está bien. Un registro que verifica
runtimes no acepta uno que el agente describe sobre sí mismo. Primero hay que darle a SPIRE el
identificador del agente, y después presentar el certificado que emite:

```bash
make spire-entry ULID=01M3D51K666A82R8VRG7EAC1PB
make spire-svid
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk -svid .spire/svid
```

```
  status     ACTIVE
  runtime    attested as spiffe://uai.test/agents/01M3D51K666A82R8VRG7EAC1PB/i/dev
```

> El orden no es caprichoso. Una entrada de registro de SPIRE nombra al agente, así que no puede
> existir antes de que el agente tenga identificador — por eso el binding es un paso aparte y no
> una opción.

**Paso 4 — mirar lo que hiciste.**

```bash
go run ./tools/uai-register show
```

Y en el navegador, pegá el UAI-ID en `http://localhost:8081/verify.html`.

En una shell donde no las exportaste, los mismos dos valores van en la línea de comando —
`-endpoint` y `-ca` le ganan al entorno:

```bash
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk \
  -svid .spire/svid -endpoint https://localhost:8080 -ca .spire/bootstrap.pem
```

Contra un gateway con TLS, dejar el CA afuera no es una versión más corta del mismo comando: el
cliente se queda sin nada contra qué verificar al gateway, y el pedido falla antes de llegar a todo
esto. `-ca` es cómo decís a qué SPIRE le creés — no un interruptor que apaga la verificación.

### Las pantallas

| Dirección | Qué es | Qué mirar |
|---|---|---|
| `http://localhost:8081/` | Inicio | El resumen, y qué dice el sistema de sí mismo |
| `http://localhost:8081/verify.html` | **Verificar** | La pantalla central: pegás un UAI-ID y dice si es válido. Esta página **comprueba las pruebas en tu navegador**, no muestra un veredicto que le pasamos |
| `http://localhost:8081/explorer.html` | Explorador | El libro de actas: las acciones registradas y sus pruebas |
| `http://localhost:8081/quarantine.html` | Cuarentenas | Agentes con restricciones preventivas, y qué se les suspendió |
| `http://localhost:8081/governance.html` | Gobernanza | Las propuestas de revocación, quién votó qué y bajo qué umbral |
| `http://localhost:8081/agent.html?id=…` | Ficha de agente | Todo lo público de una identidad |
| `http://localhost:8081/federation.html` | Federación | Este registro, sus pares y las identidades que otros anunciaron. `404 UAI_FEDERATION_NOT_CONFIGURED` si la instalación no tiene número |

> La página de verificación es la única del sistema que **no hace falta creerle a nadie**. El código
> que comprueba las firmas corre en tu navegador y se puede leer: son unos pocos cientos de líneas
> sin librerías externas, en [`web/app/verify.js`](../web/app/verify.js).

### Probarlo con la línea de comandos

Preguntarle al sistema por una identidad que no existe:

```bash
curl -s http://localhost:8080/v1/verify/uai:agent:01ZZZZZZZZZZZZZZZZZZZZZZZZ
```

```json
{
  "identity": "uai:agent:01ZZZZZZZZZZZZZZZZZZZZZZZZ",
  "verified": false,
  "status": "UAI_UNVERIFIED",
  "note": "No verifiable UAI identity exists for this identifier; this is not an assertion that the agent is malicious."
}
```

Fijate en la última línea. **El silencio no es una acusación.** Que un sistema no conozca a un
agente no significa que ese agente sea malicioso, y decirlo explícitamente evita que alguien lea lo
contrario.

### Las pruebas que se pueden correr

Cada una falla si algo anda mal. Ninguna es decorativa.

```bash
make demo        # el escenario completo: 21/21 criterios
make walkthrough # el mismo escenario, de a un criterio, sobre tu propio stack
make attested    # que el runtime lo certifique SPIRE y no el propio agente: 7/7
make pentest     # 16 ataques desde afuera; falla si alguno funciona
make invariants  # 88 operaciones prohibidas; falla si alguna se permite
make check       # todo lo que tiene que pasar antes de un commit
```

**`make walkthrough`** es `make demo` a velocidad de lectura. Para en cada uno de los 21
criterios, imprime la llamada que acaba de hacer como un comando que podrías haber tipeado vos
—un `curl` de verdad, un `psql` de verdad, o el SDK cuando la llamada va firmada—, muestra lo que
volvió, y te dice qué página abrir antes de que aprietes Enter. Esa es la diferencia que importa:
`make demo` se arma una base y un gateway descartables y los destruye, así que nada de lo que hace
se ve nunca en el navegador. El walkthrough escribe sobre el stack que tenés corriendo, que es el
que leen las páginas.

El precio es que lo que crea se queda. UAI no borra identidades, así que un walkthrough deja atrás
una organización, un dueño y un agente revocado — y eso es la garantía funcionando, no una fuga.
Las llamadas firmadas se imprimen como lo que mandó el SDK y no como un `curl` para pegar: la
firma cubre el método, la URL y el cuerpo, así que una copia no validaría.

**`make pentest`** es la más ilustrativa para alguien que quiere entender qué protege el sistema.
Ataca a una API real desde afuera, con lo único que tendría un atacante: una identidad propia y
legítima. Intenta reusar firmas, repetir pedidos capturados, bindear la identidad de otro, votar
con una credencial real pero sin humano presente. Los 16 son rechazados, y el informe muestra
cada uno con el error exacto.

**`make invariants`** es la otra cara: pregunta qué le niega la **base de datos** a alguien que ya
está adentro. Por ejemplo, que un administrador con acceso total no pueda editar una evidencia ni
borrar un voto.

### Verificar desde afuera, sin confiar en nosotros

Esta es la prueba que más importa, y la que define si el proyecto sirve para algo:

```bash
go build -o uai-verify ./tools/uai-verify
./uai-verify uai:agent:01JY8R9ZAF392N7QX2T81JH6KM
```

Esa herramienta **no confía en nada** salvo en tres claves públicas. Se baja lo público, rehace las
cuentas y **recalcula el veredicto en vez de mostrarlo**. Si el sistema dijera que una identidad
está revocada pero los votos no dieran 4 de 5, esta herramienta lo diría.

Y cuando termina, aclara qué comprobó y qué no:

> *Esto dice que el registro es internamente consistente y está firmado por las claves que nombra —
> no que las acciones descritas hayan tenido los efectos que dicen.*

---

## 5. Qué está terminado y qué no

Ser claro acá es parte del diseño: un proyecto de identidad que exagera lo que tiene pierde la
credibilidad una sola vez.

### Terminado y probado

Identidad, credenciales, pasaportes, atestación de acciones, criptografía y vectores de referencia,
guardarraíl con reglamento firmado, contratos y anclaje, las siete pantallas, tres SDKs y servidor
MCP, la demo de 21 criterios, los gates de seguridad, atestación de runtime con SPIRE, y el primer
paso de federación (identidad de registro, peering explícito y un anuncio firmado entre dos pares).

### Lo que falta, y qué significa

| Falta | Qué implica hoy |
|---|---|
| **Prueba de control de dominio** | Cuando una empresa dice ser dueña de `empresa.com`, nadie lo comprueba. Es una afirmación |
| **Aviso al dueño al registrar** | Si alguien registra un agente a nombre de tu empresa, queda visible pero nadie te avisa |
| **Límites de frecuencia** | Nada frena a quien quiera registrar mil agentes o inundar de denuncias |
| **Firma de artefactos (SBOM)** | Sabemos qué proceso corre, no de qué código fue construido |
| **Contra-atestación** | Un agente que solo registra lo que le conviene deja huecos visibles, pero nadie los mira |
| **Detección de clones entre instalaciones** | Se detecta en principio y no lo hace nadie |

**Consecuencia directa:** como la verificación del dueño no existe (§3.11), **toda identidad está
en AL0**, incluso una con llave en HSM y runtime atestado. El registro no se limita a decir el
nivel: dice qué dimensión es el techo.

```json
"assurance_level":      "UAI-AL0",
"assurance_limited_by": "owner verification",
"assurance_detail":     "the owner is self-asserted; nothing has demonstrated control of its DID"
```

> *"el dueño es auto-declarado; nadie demostró control de su DID"*

Eso no es un error: es el sistema negándose a afirmar algo que no puede probar. Un `UAI-AL0` a
secas sería indistinguible de una mala configuración; con el motivo al lado, quien lo lee sabe qué
tendría que cambiar, y el dueño sabe qué tiene que ir a hacer.

### Lo que todavía no es real

Los testigos y los validadores corren todos en la misma máquina, así que **la independencia que da
sentido a los testigos todavía no existe**. La prueba de fuego del proyecto no es técnica: es que
*otra organización* opere un validador y un testigo en su propia infraestructura. Eso es la
Fase 13.

---

## 6. Si algo no funciona

| Síntoma | Causa y solución |
|---|---|
| `make dev` falla con `type "agent_status" already exists` | Base vieja sin registro de migraciones. `make migrate-baseline`, o `./deploy.sh nuke` para empezar de cero (borra los datos) |
| `./deploy.sh up` se queda sin espacio | Los contenedores viejos dejan volúmenes huérfanos. `podman volume prune` los borra; revisá la lista antes, por si hay alguno de otro proyecto |
| El gateway sale con `permission denied` sobre `/keys/issuer.jwk` | La clave se copia a un volumen del servicio al arrancar. Volver a correr `./deploy.sh up` lo rehace |
| El gateway no arranca y habla de la clave del emisor | La clave nunca se genera sola al arrancar, a propósito: una clave que cambia en cada reinicio emite credenciales que después no validan. `make issuer-key` |
| El gateway avisa `runtime attestation disabled` | Es normal y está bien. Sin SPIRE configurado registra runtimes auto-declarados; la advertencia existe para que la diferencia no sea invisible |
| `package slices is not in GOROOT (/usr/src/slices)` | El `go` que se está usando es **gccgo**, que instalan los paquetes `golang-go` y `gccgo-go` de Ubuntu en `/usr/bin/go`. Es otro compilador y no puede construir esto. `make check-go` dice qué toolchain va a usar la build; instalá uno oficial de <https://go.dev/dl/> y ponelo antes de `/usr/bin` en el PATH |
| `uai-register` se niega diciendo que corre como root | Usaste `sudo`, y acá no hace falta para nada: la base se alcanza por TCP y las llaves van a tu directorio de trabajo. Bajo sudo la llave se escribe como root y después no la podés leer — y eso aparece mucho más tarde, como un error de permisos sobre un archivo que en `ls` se ve bien |
| `uai-register agent` falla con `403 UAI_OWNER_NOT_ELIGIBLE` | El dueño que nombra `-owner-did` no está en esta base — casi siempre porque lo borró `./deploy.sh nuke` mientras las llaves quedaron en disco. `uai-register show` lista los dueños que existen; volvé a registrar el tuyo con `-reuse-key` |
| `uai-register owner` dice `.keys/owner.jwk already exists` | Está bien, y no lo va a pisar: esa llave responde por todos los agentes que cuelgan de ella. Si el dueño todavía existe, el mensaje te dice cuál es — registrá un agente bajo ese. Si no existe ninguno, volvé a registrar la llave con `-reuse-key` |
| `./deploy.sh status` dice que hay un agente SPIRE corriendo pero el gateway arrancó antes | El gateway fija su modo una sola vez, al arrancar. Levantar el agente después no atestigua nada hasta que `./deploy.sh up` lo reinicie — y eso conserva los datos |
| `make demo` dice que el puerto está ocupado | Quedó una corrida anterior. El propio target intenta limpiarla; si no, `make demo DEMO_PORT=9999` |
| `./deploy.sh nuke` dejó las llaves | A propósito: una llave privada borrada no se recupera, y el mismo archivo puede seguir nombrando a un dueño en otra base. Volvé a registrarlas con `-reuse-key`, o borralas deliberadamente con `./deploy.sh nuke --keys`, que nombra cada archivo que saca |
| `UAI_KEY_NOT_UNIQUE` | Esa llave ya nombra a otra identidad. Una llave nombra a una sola: dos identidades compartiéndola hacen que una firma no diga cuál de las dos firmó, y que revocar una deje a la otra operando con la misma llave |
| Todo raro después de tocar cosas | `make nuke && make dev` — borra los volúmenes y arranca limpio |

---

## 7. Para seguir

- [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md) — la misma plataforma desde el otro lado: un
  dueño, un agente y una acción, paso a paso, con cada comando y su salida real.
  Escrito en español
- [`README.md`](../README.md) — el resumen del proyecto
- [`docs/protocol/`](protocol/) — la especificación completa, 26 secciones (en inglés: está
  pensada para presentarse ante organismos internacionales)
- [`docs/protocol/13-threat-model.md`](protocol/13-threat-model.md) — qué puede salir mal, qué lo
  frena, y qué controles **todavía no existen**
- [`docs/security/pentest-checklist.md`](security/pentest-checklist.md) — qué se ataca
  automáticamente y qué necesita una persona
- [`SECURITY.md`](../SECURITY.md) — cómo reportar una vulnerabilidad

> Si encontrás una forma de romper alguna de las diez reglas del modelo de amenazas, ese es
> exactamente el reporte que más queremos.
