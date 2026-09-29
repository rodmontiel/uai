# Ejemplo práctico: federar dos registros UAI

> *Este documento se corrió entero antes de escribirse. Cada salida que ves abajo es la que
> devolvieron los comandos.*
>
> Continúa a [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md), que muestra **una** instalación
> UAI administrando agentes. Este muestra **dos**, administradas por separado, reconociéndose y
> compartiendo una afirmación firmada sobre una identidad — sin que ninguna se vuelva la base de
> datos de la otra.

---

## La idea en una frase

Hoy una instalación UAI responde *"¿quién es este agente?"*. Falta que pueda responder
**"¿quién es este registro?"** — y que dos registros puedan reconocerse entre sí.

🍎 **Con manzanas:** cada ferretería lleva su propio libro de empleados. Nadie tiene un libro
central de todas las ferreterías del país, y nadie lo quiere. Lo que sí quieren es poder
decirse: *"este carnet lo emití yo, y esta es mi firma"*. La otra ferretería lo anota en un
cuaderno aparte que dice **"lo que me contaron"**, no en su propio libro de empleados.

Ese cuaderno aparte es la mitad del trabajo de este microsprint. La otra mitad es que la firma
sea comprobable.

---

## Lo que este microsprint hace, y lo que no

| Hace | No hace |
|---|---|
| Cada instalación tiene un número propio (**UAI-AS**) y una llave | Descubrimiento automático de registros |
| Dos registros se configuran mutuamente, a mano | Tránsito, rutas, caminos, confederaciones |
| Un handshake firmado lleva el peering de `PENDING` a `ACTIVE` | Propagación de cuarentenas o revocaciones |
| Un registro anuncia una identidad **que él emitió** | Propagación de políticas o pasaportes |
| El receptor verifica y guarda la afirmación **como afirmación** | Tratar una identidad federada como agente propio |

No es un BGP para agentes. Es el apretón de manos que tendría que existir antes de pensar en uno.

---

## La distinción que sostiene todo

```
PEER TRUST        este registro puede mandarme afirmaciones firmadas
      ≠
AGENT TRUST       le creo lo que dice sobre un agente en particular
```

Configurar un peer es lo primero. **Nunca implica lo segundo.** Una identidad federada aceptada
queda en su propia tabla, sin capacidades, sin credenciales locales, y este registro no puede
revocarla — solo el que la emitió puede decir algo sobre ella.

---

## Correrlo entero, de una

```bash
make federation-demo
```

Levanta dos postgres y dos gateways, hace los siete pasos y prueba las negativas. Para dejarlo
andando y mirar las pantallas:

```bash
make federation-demo-keep
# …
make federation-demo-down
```

El resto de este documento es lo mismo, paso a paso, para entender qué hace cada pieza.

---

## Paso 1 — Cada registro dice quién es

🍎 **Con manzanas:** cada ferretería pone un cartel con su número de habilitación y su sello.

**Lo que pasa de verdad:** la instalación toma un **UAI-ASN** de la configuración y una llave
privada de un archivo. El número es de UAI, no de Internet: tomar ASNs reales insinuaría una
autoridad para asignarlos que nadie acá tiene.

```bash
UAI_ASN=1001 UAI_REGISTRY_NAME="OMniLeads-UAI" \
UAI_REGISTRY_KEY=.keys/registry-1001.jwk \
UAI_FEDERATION_ENDPOINT=http://127.0.0.1:8091 \
  ./gateway -addr 127.0.0.1:8091
```

La llave se crea una vez, y **no es la del emisor de credenciales**:

```bash
go run ./tools/uai-keygen -out .keys/registry-1001.jwk -did did:uai-registry:1001
```

> Dos llaves y no una, a propósito. La del emisor firma credenciales **sobre agentes**; la del
> registro firma lo que esta instalación dice **de sí misma** a sus pares. Una sola llave haría
> que comprometer el camino federado comprometiera además toda credencial jamás emitida acá.

Ahora cada uno se presenta:

```bash
go run ./tools/uai-federate show
```

```
  UAI-AS      1001
  registry    OMniLeads-UAI
  did         did:uai-registry:1001
  status      ACTIVE
  endpoint    http://127.0.0.1:8091
  protocol    0.1
```

Y por HTTP, que es como lo ve un par:

```bash
curl -s http://127.0.0.1:8091/v1/federation/registry
```

> Si la instalación no tiene `UAI_ASN`, **todas** las rutas de federación devuelven 404 con
> `UAI_FEDERATION_NOT_CONFIGURED`. Es el estado honesto: una instalación a la que nadie le dio
> un número no se unió a nada en silencio.

---

## Paso 2 — Configurar el peering, a mano

🍎 **Con manzanas:** las dos ferreterías se intercambian el sello en persona. No lo buscan en
una guía.

**Lo que pasa de verdad:** se guarda el ASN del otro, su DID, su endpoint y **su llave pública**.
Esa llave es contra la que se van a verificar todos sus mensajes. Un peering que tomara la llave
del mensaje que está verificando verificaría todos los mensajes, incluidos los falsos.

```bash
go run ./tools/uai-federate peer add \
  -asn 2001 \
  -endpoint-remote http://127.0.0.1:8092 \
  -pubkey partner-2001.jwk
```

Para probar, `-trust-on-first-use` la baja del endpoint — y lo dice en voz alta, porque confía
en quien conteste esa URL en ese momento:

```
  trust on first use: taking AS2001's key from http://127.0.0.1:8092.
  Whoever answers that URL now becomes the key every later message is
  checked against. Out of band is better.
  peer        AS2001  PENDING
  endpoint    http://127.0.0.1:8092

  PENDING until a handshake. And a peering is not trust in its agents:
  it only means this registry will read what that one sends.
```

> **Este comando va firmado con la llave de TU registro.** Un `POST /v1/federation/peers` sin
> autenticar dejaría que cualquiera se agregue como par de confianza — y después toda
> verificación posterior pasaría, porque estaría verificando contra la llave que el atacante
> acaba de registrar. Decidir a quién escuchar es un acto de la instalación, y la única llave
> que habla por ella es la del registro.

Hay que hacerlo **de los dos lados**. Cada registro decide por su cuenta a quién escucha.

---

## Paso 3 — El handshake

🍎 **Con manzanas:** cada una manda una carta lacrada con su sello. La otra compara el lacre
contra el sello que ya tenía anotado.

**Lo que pasa de verdad:** se manda un `REGISTRY_HELLO` firmado, y el receptor chequea, en este
orden:

1. **Forma y frescura** — tipo, versión de protocolo, que el DID y el ASN no se contradigan, y
   que el reloj esté dentro de 5 minutos.
2. **Que el remitente ya sea un par configurado.** Un registro desconocido se rechaza acá,
   antes de leer ninguna llave.
3. **La firma**, contra la llave que se guardó al configurar el peering — nunca contra la que
   viene adentro del mensaje.
4. **El nonce**, para que un hello capturado no se pueda repetir.

Recién entonces `PENDING` → `ACTIVE`.

```bash
go run ./tools/uai-federate handshake -asn 2001
```

```
  sent        REGISTRY_HELLO from AS1001
  answered    REGISTRY_HELLO from AS2001 (Partner-UAI)
  peering     AS1001 is now ACTIVE at the far end

  Run the same command from the other side to make it ACTIVE here too:
  a handshake proves one direction, and both registries decide separately.
```

```bash
go run ./tools/uai-federate peers
```

```
  UAI-AS   REGISTRY DID                       STATUS     ENDPOINT
  1001     did:uai-registry:1001              ACTIVE     http://127.0.0.1:8091
```

---

## Paso 4 — AS1001 tiene una identidad propia

Nada nuevo acá: es el flujo de [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md).

```bash
go run ./tools/uai-register owner -name "ACME Robotics" -org-did did:web:acme-fed.example
go run ./tools/uai-register agent -owner-did did:uai:owner:… -name "ALPHA"
```

```
  uai-id     uai:agent:01M3Q13DBP0MPWJJ5A8E930MP4
```

Federado, esa identidad se escribe nombrando a su registro:

```
did:uai:1001:agent:01M3Q13DBP0MPWJJ5A8E930MP4
         ^^^^
         quién responde por ella
```

---

## Paso 5 — El anuncio

🍎 **Con manzanas:** *"el carnet número tal lo emití yo, está vigente, y acá va mi firma"*. No
dice qué hace el empleado, ni a qué clientes atendió, ni cuánto cobra.

**Lo que pasa de verdad:** un `IDENTITY_ANNOUNCEMENT` firmado, con exactamente siete campos y
ninguno libre.

```bash
go run ./tools/uai-federate announce -uai-id uai:agent:01M3Q13DBP… -to 2001 -sequence 1042
```

```
  announced   did:uai:1001:agent:01M3Q13DBP0MPWJJ5A8E930MP4
  status      REGISTERED
  sequence    1042
  to          AS2001 → ACCEPTED
```

> **No hay campo libre, y eso es la garantía.** "El anuncio no debe contener prompts,
> conversaciones, PII ni secretos" es una regla que se cumple sola porque el decodificador
> **rechaza miembros desconocidos**: mandale un `"conversation"` de más y el mensaje entero se
> rechaza. Un decodificador que los ignorara los aceptaría, no guardaría nada, y dejaría al
> emisor creyendo que llegaron.

Lo único que viaja del contenido es el `credential_hash`: un compromiso, no la credencial.

---

## Paso 6 — Lo que AS2001 verifica

```
1. El registro origen es un par conocido          → UNKNOWN_PEER si no
2. El peering está ACTIVE                         → PEER_NOT_ACTIVE si no
3. La firma es válida                             → INVALID_SIGNATURE si no
4. El timestamp es razonable                      → STALE_TIMESTAMP si no
5. El sequence avanza                             → STALE_SEQUENCE si no
6. El DID nombra al registro que lo anuncia       → WRONG_AUTHORITY si no
7. El payload no trae nada más                    → INVALID_PAYLOAD si no
```

El punto 6 es el que más importa y el menos obvio: **una firma válida no es autoridad.** AS2001
puede firmar perfectamente un anuncio sobre un agente de AS1001. Se rechaza igual, porque el DID
dice de quién es la identidad, y no es suya.

---

## Paso 7 — Lo que AS2001 guarda

```bash
go run ./tools/uai-federate identities
```

```
  AGENT DID                                      ORIGIN   STATUS       SIGNATURE
  did:uai:1001:agent:01M3Q13DBP0MPWJJ5A8E930MP4  AS1001   REGISTERED   VERIFIED

  These belong to other registries. None of them is an agent of this one.
```

Y en el navegador: `http://localhost:8081/federation.html`.

🍎 **El cuaderno aparte.** La tabla `federated_identities` no tiene ninguna relación con
`agents`. Un operador que pidiera "todos mis agentes" y recibiera identidades de otro registro
estaría tomando decisiones sobre procesos que no corre, con la palabra de un registro con el que
apenas intercambia mensajes.

---

## Las tres negativas, probadas

`make federation-demo` no termina en el camino feliz:

```
==> and what AS2001 refuses
    ✓ a replayed announcement: STALE_SEQUENCE
    ✓ AS2001 trying to revoke AS1001's identity: WRONG_AUTHORITY
    ✓ AS2001 has 0 local agents: a federated identity is not one (FED-002)
```

**El replay** importa más de lo que parece: sin el número de secuencia, un anuncio capturado se
puede reenviar para mover una identidad **de vuelta** a un estado que ya dejó — convertir una
revocada en activa reenviando el mensaje de ayer.

---

## Las tres invariantes

**FED-001** — Nunca aceptar un anuncio sin firma válida.
**FED-002** — Nunca tratar una identidad federada como una local.
**FED-003** — Agregar un par no implica confiar en sus agentes.

No son comentarios. FED-002 está en el esquema (tablas separadas, sin clave foránea, y un CHECK
que ata el DID a su origen), y las tres tienen tests que fallan si se las saca.

---

## Auditoría

Toda operación federada usa la tabla `audit_events` que ya existía — que, hasta este
microsprint, **nadie escribía**. Se registran, firmadas:

```
PEER_CREATED                        PEER_HANDSHAKE_SUCCEEDED
PEER_HANDSHAKE_FAILED               FEDERATION_ANNOUNCEMENT_ACCEPTED
FEDERATION_ANNOUNCEMENT_REJECTED
```

Los rechazos también. Un registro que solo anota lo que aceptó es publicidad.

```bash
podman exec uai-fed-b psql -U uai -d uai -c \
  "SELECT operation, outcome, detail->>'reason' FROM audit_events ORDER BY occurred_at DESC LIMIT 5"
```

---

## Lo que queda explícitamente afuera

`REGISTRY_PATH` · registros de tránsito · algoritmo de ruteo tipo BGP · RPKI · confederaciones ·
route reflectors · descubrimiento automático · comunidades de confianza · motor de políticas
import/export · propagación de cuarentenas · propagación de revocaciones · federación de
pasaportes · multi-path · looking glass · consenso de blockchain federado.

Las interfaces quedaron extensibles. Nada de eso está implementado, y ningún texto de este repo
dice que sí.

---

## Si algo falla

| Síntoma | Causa y solución |
|---|---|
| `404 UAI_FEDERATION_NOT_CONFIGURED` | Esa instalación no tiene `UAI_ASN`. Es un estado válido, no una falla |
| `401 UAI_FEDERATION_NOT_AUTHORIZED` al agregar un par | El comando va firmado con la llave del registro. Usá `uai-federate peer add`, que la tiene, y revisá `-key` |
| `403 UNKNOWN_PEER` | El otro registro no te configuró a vos. El peering se hace de los dos lados |
| `403 PEER_NOT_ACTIVE` | Falta el handshake: `uai-federate handshake -asn N` |
| `409 STALE_SEQUENCE` | Ese número de secuencia ya se usó. Cada anuncio tiene que avanzar |
| `403 WRONG_AUTHORITY` | Estás anunciando una identidad que no emitiste. Un registro habla por lo suyo |
| `401 INVALID_SIGNATURE` | La llave guardada para ese par no es la que firmó. Volvé a configurar el peering con la llave correcta |
| `STALE_TIMESTAMP` | Relojes separados por más de 5 minutos |

---

## Para seguir

- [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md) — una sola instalación, de la A a la Z
- [`MANUAL.es.md`](MANUAL.es.md) — qué es cada pieza y por qué existe
