# Manual de usuario

> *También disponible en inglés: [`MANUAL.md`](MANUAL.md).*
>
> Este documento explica UAI **desde cero**, sin dar por sabido nada. Está escrito para que lo
> entienda alguien que no programa. Los tecnicismos aparecen, pero siempre acompañados de qué
> hacen y a qué se parecen.

---

## 1. El problema, en una frase

Un programa de inteligencia artificial hizo algo. **¿Quién fue, y quién responde?**

Hoy, en la práctica, no hay respuesta. Un agente de IA que manda un correo, mueve plata o borra un
archivo deja como rastro, con suerte, una línea en un log que dice `bot-27`. Esa línea la escribió
el mismo sistema que hizo la acción. Es como un recibo que se firmó a sí mismo.

UAI existe para que esa pregunta tenga respuesta, y para que la respuesta se pueda **comprobar sin
confiar en nosotros**.

### Lo que UAI NO hace

Esto va primero, no al final, porque es lo que más fácil se malentiende:

- **UAI no dice que un agente sea seguro.** Ningún protocolo puede. Dice *quién es*, *quién
  responde por él*, *qué se le permitió* y *qué hizo*.
- **UAI no tiene un botón de apagado global.** No existe, y no puede existir. Revocar una
  identidad significa que *los demás dejan de aceptarla* — no que el programa se detenga. Si el
  agente corre en una computadora desconectada, sigue corriendo. La demo lo muestra a propósito.

> Analogía: si a alguien le anulan el pasaporte, no se desintegra. Simplemente deja de poder
> cruzar fronteras donde lo revisan. UAI es el sistema de pasaportes, no la policía.

---

## 2. Las cuatro cosas que UAI le da a un agente

| Se llama | Se parece a | Qué es realmente |
|---|---|---|
| **UAI-ID** | Un número de documento | Un identificador único e irrepetible. No dice nada de la persona: es el número al que se le cuelga todo lo demás |
| **Credencial** | Un título o un carnet | Un documento firmado que dice de quién es ese agente y qué se le habilitó |
| **Pasaporte** | Un pasaporte | Un permiso con fecha de vencimiento para actuar en ciertos países. Dice **dónde**, nunca **qué** |
| **Atestación de acción** | Un recibo de escribano | Un registro firmado de cada cosa que hizo, encadenado al anterior |

La distinción entre credencial y pasaporte importa y es fácil de perder:

- La **credencial** dice *"este agente puede optimizar rutas de entrega"*. Eso es el **qué**, y lo
  otorga el dueño.
- El **pasaporte** dice *"puede hacerlo en Argentina y Alemania, hasta el 3 de marzo"*. Eso es el
  **dónde y hasta cuándo**.

Un pasaporte nunca puede agregar una capacidad que el dueño no dio. Por eso el agente puede
pedirlo solo, sin que eso sea un auto-permiso.

---

## 3. De qué está hecho, pieza por pieza

Acá va cada componente con la tecnología que usa, para qué sirve, y a qué se parece.

### 3.1 Firma digital — *el sello lacrado*

**Tecnología: criptografía de clave pública (Ed25519).**

Cada agente genera **dos llaves matemáticamente emparejadas**. Una la guarda y no la muestra nunca
(la *privada*). La otra la publica (la *pública*).

Lo que hace especial al par es esto: lo que se sella con la privada, cualquiera puede comprobarlo
con la pública — **pero nadie puede fabricar el sello sin tener la privada.**

> Analogía: un sello de lacre que solo vos tenés. Todo el mundo reconoce tu escudo, nadie puede
> tallar uno igual.

UAI nunca genera las llaves de un agente. El agente se las hace solo, y **nosotros nunca vemos la
privada**. Eso es deliberado: si la tuviéramos, podríamos firmar en su nombre, y entonces una firma
ya no probaría quién actuó.

### 3.2 Canonicalización — *ponerse de acuerdo en cómo se escribe, antes de firmar*

**Tecnología: JCS, RFC 8785.**

Un problema aburrido y crítico: `{"a":1,"b":2}` y `{ "b":2, "a":1 }` dicen lo mismo, pero son
textos distintos, así que producen sellos distintos. Si el que firma y el que verifica escriben el
documento de forma levemente diferente, la firma no valida — y parece un fraude cuando es solo un
espacio de más.

JCS es una regla que dice exactamente cómo escribir el documento antes de sellarlo: en qué orden
van los campos, cuántos espacios, cómo se escriben los números.

> Analogía: antes de firmar un contrato, las dos partes acuerdan la tipografía, el tamaño de hoja
> y el orden de las cláusulas. Suena burocrático. Es lo que hace que dos copias sean comparables.

Está implementado **tres veces** en este repositorio — en Go, en Python y en TypeScript — y las
tres se prueban contra los **mismos ejemplos de referencia**. Así es como se evita que tres
implementaciones se conviertan en tres protocolos distintos.

### 3.3 Separación de dominios — *para qué sirve esta firma*

Cada firma lleva adentro una etiqueta que dice para qué se hizo: `UAI-v1:attestation`,
`UAI-v1:vote`, `UAI-v1:quarantine`.

> Analogía: firmar un cheque y firmar un permiso de viaje. Aunque sea la misma mano, no querés que
> alguien pueda recortar tu firma de uno y pegarla en el otro.

Sin esa etiqueta, una firma hecha para reportar una sospecha podría reusarse como si fuera la orden
de cuarentena que viene después.

### 3.4 La cadena de eventos — *las hojas numeradas de un cuaderno*

Cada acción de un agente se guarda con el **resumen de la acción anterior** metido adentro.

> Analogía: un cuaderno donde cada página arriba escribe el resumen de la página anterior. Si
> alguien arranca una hoja, la siguiente ya no cierra. No se puede borrar en silencio.

Si el mismo agente aparece corriendo en dos lugares a la vez, la cadena se bifurca — y una cadena
bifurcada **no tiene explicación inocente**. Es la señal de que alguien clonó la identidad.

### 3.5 El registro de transparencia — *el libro de actas público*

**Tecnología: árbol de Merkle (RFC 6962), lo mismo que usan los certificados de internet.**

Todo lo que se registra entra en una estructura que permite dos cosas notables:

1. Demostrar que **algo está adentro**, sin mostrar todo lo demás.
2. Demostrar que el libro **solo creció**, que nunca se reescribió una página vieja.

> Analogía: un libro de actas donde cada página lleva un número que depende de todas las anteriores.
> Cambiar una coma en la página 3 cambia el número de la última página, y todo el mundo lo ve.

**El registro no guarda el contenido.** Guarda solamente una huella. Si alguien se roba la base de
datos del registro, no se lleva ni un prompt ni un dato personal.

### 3.6 Testigos — *firmar el mismo libro desde otra oficina*

Un libro de actas tiene un problema: ¿y si el que lo lleva te muestra una versión a vos y otra
distinta a otro? Eso se llama *vista partida*, y la criptografía sola no lo detecta.

La solución no es técnica sino organizativa: **otros firman el mismo libro**. Si el registro
intentara mostrar dos historias, tendría que conseguir que los testigos firmaran las dos.

> Analogía: dos escribanos de estudios distintos firman el mismo acta. Falsificarla deja de ser un
> problema de uno y pasa a ser una conspiración.

Hoy en este repositorio los testigos corren en la misma máquina, y **eso no vale como
independencia**. Está anotado como pendiente, no disimulado.

### 3.7 Anclaje en blockchain — *clavar el libro en la plaza*

Cada tanto, la huella del libro de actas se publica en una cadena de bloques.

> Analogía: pegar en la puerta del juzgado un papel que dice "a las 15:00 el libro de actas iba por
> la página 4.812 y su huella era ésta". Si después alguien reescribe el libro, el papel de la
> puerta lo contradice.

**En la cadena no va contenido**, solo huellas con sal. Eso está garantizado por una prueba
automática que rechaza cualquier contrato que declare un parámetro capaz de llevar texto.

> Lo de "con sal" importa: la huella de un dato adivinable (un email, por ejemplo) se puede
> descubrir probando con un diccionario. Agregarle un valor secreto al azar antes de calcularla lo
> hace inviable.

### 3.8 El guardarraíl — *el reglamento, y el que lo aplica*

**Tecnología: OPA / Rego, un motor de reglas.**

Antes de cada acción, el agente pregunta: *"¿puedo hacer esto?"*. Quien contesta es un motor de
políticas que consulta un **reglamento firmado**.

El reglamento no es un archivo que cualquiera edite: está firmado por varios custodios
independientes, y el motor **se niega a cargarlo** si las firmas no dan. Editar una regla sin
volver a firmar rompe el arranque.

> Analogía: el reglamento de un club, firmado por tres miembros del consejo. El portero no lo aplica
> porque esté impreso: lo aplica porque reconoce las firmas.

Y cada decisión que toma queda registrada **con la versión exacta del reglamento** que se usó. Sin
eso, revisar una decisión de hace dos años sería imposible: no se sabría contra qué reglas se tomó.

### 3.9 La gobernanza — *revocar requiere gente, no software*

Para revocar una identidad de forma permanente hacen falta **4 votos de 5 delegados, de al menos 3
países distintos**.

**Tecnología: WebAuthn**, el mismo estándar de las llaves físicas de seguridad y del lector de
huella del teléfono.

Acá hay un detalle de diseño que es el corazón del sistema: **el desafío que firma la llave física
ES el resumen del voto**. No es "iniciar sesión y después votar". Es que el aparatito firma
exactamente *el contenido de lo que se está votando*.

> Analogía: en vez de mostrar el documento en la puerta y después firmar cualquier papel adentro, la
> lapicera solo escribe si le apoyás el dedo **sobre ese papel concreto**.

Consecuencia práctica: **ningún programa puede votar.** Un proceso automático puede tener la
credencial del delegado y aun así no puede producir un voto válido, porque el aparato exige la
verificación de un humano presente. El sistema lo rechaza con un error que lo dice con todas las
letras.

> El administrador del sistema es de solo lectura por construcción. Lo único que puede hacer con una
> revocación es ejecutar una que ya fue decidida, y el contrato vuelve a verificar las firmas de los
> delegados antes de aceptarla. Un administrador comprometido no puede revocar a nadie.

### 3.10 Atestación de runtime — *el carnet te lo da el edificio, no vos*

**Tecnología: SPIFFE/SPIRE.**

Hasta hace poco, cuando un agente se conectaba y decía *"estoy corriendo en tal lugar, con tal
programa"*, el sistema le creía. Estaba firmado... **por el propio agente**. Es un formulario que
uno llena sobre sí mismo.

SPIRE cambia eso. Es un servicio que mira el proceso **desde afuera** —le pregunta al sistema
operativo quién lo está ejecutando, desde qué archivo, con qué usuario— y solo entonces le entrega
un certificado de corta duración.

> Analogía: la diferencia entre escribir tu nombre en una lista al entrar a un edificio, y que
> recepción te saque una foto, chequee tu documento y te imprima un carnet con vencimiento. Lo
> segundo no lo podés falsificar solo.

Lo que esto bloquea, concretamente: un agente que tiene un certificado **perfectamente válido** ya
no puede usarlo para hacerse pasar por otro. El sistema comprueba que el certificado *nombre a esa
identidad*, y si no, lo rechaza.

### 3.11 El SDK — *el enchufe*

Un SDK es la pieza que un desarrollador mete en su programa para hablar con UAI. Hay tres (Python,
TypeScript, Go) y un servidor MCP para agentes que usan ese estándar.

El diseño parte de admitir algo incómodo: **un SDK no puede obligar a un agente a rendir cuentas**,
porque corre dentro del propio agente. Lo único que se puede hacer es que el camino honesto sea el
más cómodo. Por eso la forma es ésta:

```python
with agent.action("enviar cotización al cliente") as act:
    resultado = hacer_el_trabajo()
```

Consultar la política, registrar el resultado y firmarlo pasa **solo**, incluso si el trabajo
falla. No hay que acordarse de nada. Un diseño donde hubiera que llamar a "registrar" al final
sería un diseño donde las acciones que salen mal no se registran.

---

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
./deploy.sh nuke     # apagar y borrar los datos
./deploy.sh status   # qué está corriendo y en qué puertos
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

```bash
export PG_DSN="postgres://uai:uai@localhost:5432/uai?sslmode=disable"
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

> Cuando el gateway sirve TLS —cosa que hace siempre que la atestación está encendida— agregale
> `-endpoint https://localhost:8080 -ca .spire/bootstrap.pem` a cada comando de `uai-register`.
> `./deploy.sh status` te dice en cuál de los dos estás.

### Las cinco pantallas

| Dirección | Qué es | Qué mirar |
|---|---|---|
| `http://localhost:8081/` | Inicio | El resumen, y qué dice el sistema de sí mismo |
| `http://localhost:8081/verify.html` | **Verificar** | La pantalla central: pegás un UAI-ID y dice si es válido. Esta página **comprueba las pruebas en tu navegador**, no muestra un veredicto que le pasamos |
| `http://localhost:8081/explorer.html` | Explorador | El libro de actas: las acciones registradas y sus pruebas |
| `http://localhost:8081/quarantine.html` | Cuarentenas | Agentes con restricciones preventivas, y qué se les suspendió |
| `http://localhost:8081/governance.html` | Gobernanza | Las propuestas de revocación, quién votó qué y bajo qué umbral |
| `http://localhost:8081/agent.html?id=…` | Ficha de agente | Todo lo público de una identidad |

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
make attested    # que el runtime lo certifique SPIRE y no el propio agente: 7/7
make pentest     # 16 ataques desde afuera; falla si alguno funciona
make invariants  # 88 operaciones prohibidas; falla si alguna se permite
make check       # todo lo que tiene que pasar antes de un commit
```

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
guardarraíl con reglamento firmado, contratos y anclaje, las cinco pantallas, tres SDKs y servidor
MCP, la demo de 21 criterios, los gates de seguridad, y atestación de runtime con SPIRE.

### Lo que falta, y qué significa

| Falta | Qué implica hoy |
|---|---|
| **Prueba de control de dominio** | Cuando una empresa dice ser dueña de `empresa.com`, nadie lo comprueba. Es una afirmación |
| **Aviso al dueño al registrar** | Si alguien registra un agente a nombre de tu empresa, queda visible pero nadie te avisa |
| **Límites de frecuencia** | Nada frena a quien quiera registrar mil agentes o inundar de denuncias |
| **Firma de artefactos (SBOM)** | Sabemos qué proceso corre, no de qué código fue construido |
| **Contra-atestación** | Un agente que solo registra lo que le conviene deja huecos visibles, pero nadie los mira |
| **Detección de clones entre instalaciones** | Se detecta en principio y no lo hace nadie |

**Consecuencia directa y honesta:** el nivel de garantía es el **mínimo** entre tres dimensiones
—cómo se guarda la llave, cómo se verificó al dueño, y cómo se certificó el runtime—. Como la
verificación del dueño no existe todavía, **todas las identidades están en el nivel más bajo
(AL0)**, incluso una con llave de hardware y runtime certificado.

El sistema no se limita a decir el nivel: dice **qué dimensión lo está frenando**. Consultando un
agente registrado, la respuesta trae estos tres campos (la API responde en inglés):

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
| Todo raro después de tocar cosas | `make nuke && make dev` — borra los volúmenes y arranca limpio |

---

## 7. Para seguir

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
