# Patrones de diseño en el servicio de IA y el agente

Los patrones principales del proyecto están en el backend (`WiFiSense-backend/PATTERNS.md`: Factory Method, Decorator,
Strategy, State, Observer, Facade, Adapter, Template Method y Proxy con Circuit Breaker). Aquí están los del servicio
de IA (Python, FastAPI) y del agente: cada uno con el problema que resuelve, dónde está y la prueba que lo demuestra.

| Patrón | Dónde | Problema que resuelve | Prueba |
|---|---|---|---|
| **Null Object** | `app/llm_advisor.py`: `RuleAdvisor` | Sin clave de Claude no hay asesor; antes era `None` y cada endpoint preguntaba si existía | `test_llm_advisor.py`, `test_api.py` |
| **Strategy** | `app/llm_advisor.py`: `Advisor` (`RuleAdvisor` o `ClaudeAdvisor`) | Quién escribe la recomendación se decide al arrancar, sin `if` en los endpoints | `test_api.py::test_claude_is_only_asked_when_there_is_an_anomaly` |
| **Strategy** (algoritmos comparados) | `app/evaluation.py`: `candidates()` | Isolation Forest, Local Outlier Factor y One-Class SVM se evalúan con el mismo código y las mismas métricas | `test_evaluation.py` |
| **Pipeline** (tubería de filtros) | `app/preprocessing.py` → `app/model_service.py` | Toda medición pasa por los mismos pasos (orden por tiempo → imputar faltantes → logaritmo) antes del modelo, al entrenar y al detectar | `test_preprocessing.py`, `test_model_service.py` |
| **Middleware** (cadena de ASGI) | `app/main.py`: `BodyLimit` | Rechazar una solicitud de más de 8 MB antes de leerla, para cualquier endpoint presente o futuro | `test_limits_and_load.py` |

## Null Object: el asesor por reglas

**Problema.** Las recomendaciones de Claude son opcionales (`ANTHROPIC_API_KEY`). Sin clave, `ClaudeAdvisor.from_env()`
devolvía `None` y cada endpoint lo comprobaba (`claude.model if claude else "reglas"`,
`if claude and result.anomaly_detected`). Olvidar esa comprobación en un endpoint nuevo daría un error 500 justo
cuando Claude no está configurado, que es lo normal en local.

**Solución.** `RuleAdvisor` es un objeto que cumple el mismo protocolo (`Advisor`: `model` y `enrich()`) y no hace
nada: deja la recomendación que escribieron las reglas del diagnóstico. `from_env()` siempre devuelve un asesor.

**Beneficio.** Los endpoints usan el asesor sin preguntar si existe, y queda escrito en el código que las reglas son
el comportamiento por defecto (y el respaldo si Claude falla).

**Ejemplo.** Sin `ANTHROPIC_API_KEY`: `GET /api/v1/model` dice `"recommendationEngine": "reglas"` y una anomalía
trae `"recommendationSource": "RULES"`; con la clave y una anomalía, Claude escribe la recomendación
(`"CLAUDE"`); si Claude falla, vuelve a la de las reglas.

## Qué es aprendizaje automático y qué son reglas

| Resultado | Cómo se obtiene |
|---|---|
| ¿Hay una anomalía? Puntaje y severidad | **Modelo** Isolation Forest (entrenado con datos sintéticos o reales) |
| Causa probable | **Reglas** (firmas de cada falla sobre las desviaciones); es una hipótesis, no una causa confirmada |
| Calidad de la conexión, auditoría de seguridad, mejor canal | **Reglas** con umbrales documentados (`docs/modelo_calidad.md`, `docs/auditoria_seguridad.md`, `docs/canal_wifi.md`) |
| Texto de la recomendación | **Reglas**; opcionalmente **Claude** (servicio externo) cuando hay una anomalía |

## Agente

El agente es un solo programa de Python sin dependencias. Las diferencias entre Windows y Linux (comandos `netsh`
o `nmcli`, contadores del sistema) se resuelven con funciones por sistema operativo, sin clases: un patrón de
objetos ahí agregaría código sin resolver un problema. La deducción del tipo de equipo sigue un orden fijo de
evidencias (nombre o modelo que anuncia → servicios mDNS y UPnP y puertos abiertos → fabricante → MAC privada) en
`agent/device_discovery.py::decide_kind`; es una suposición y así se muestra en la página.

### Capturas técnicas (agente 2.0.0): Strategy, Adapter, Factory y Facade

Aquí sí había un problema que pedía objetos: cuatro formas de capturar con requisitos distintos, y una captura que toca
permisos, herramientas, límites, temporales y el servidor.

- **Strategy** (`capture_backends.py`): `NpcapBackend`, `PktmonBackend`, `RawSocketBackend` y `PacketSocketBackend`
  tienen la misma interfaz (`check` dice si se puede usar y por qué no; `capture` cuenta dentro de los límites).
  Agregar otra herramienta es otra clase. *Ejemplo:* en un Windows sin Npcap y con el agente como administrador,
  `check` de Npcap responde `NO_CAPTURE_TOOL` y el de pktmon responde que sí; se captura con pktmon
  (`test_capture_backends.py`).
- **Factory** (`choose_backend`, `all_backends`): elige la primera herramienta usable en orden de preferencia y, si
  ninguna sirve, el motivo más útil (`failure_without_tool`: si una existe pero falta permiso, dice `PERMISSION_DENIED`).
- **Adapter** (`NpcapLibrary`, `GatewayDnsSource`): la API en C de Npcap y el protocolo DNS vistos como métodos de
  Python. Las pruebas reemplazan `NpcapLibrary` por una falsa sin tocar ningún controlador.
- **Facade** (`traffic_capture.run_capture`): la única entrada de una captura (permiso local, herramienta, aviso en
  consola, carpeta temporal, consulta de «detente», conteo, envío y registro). Nunca lanza: todo termina en un
  resultado con su motivo. *Ejemplo:* sin `capture-consent on`, entrega `NO_CONSENT` sin tocar ninguna herramienta
  (`test_traffic_capture.py`).
- **Strategy para el router** (`router_sources.py`): `RouterSource` y `source_for` dejan el lugar para una integración
  oficial por modelo; hoy la única fuente es el DNS del router (solo lectura, sin clave), y bloquear o listar clientes
  lanza `NotSupported` en lugar de fingir.

## Analizados y no implementados

| Patrón | Motivo |
|---|---|
| Singleton para el modelo | El modelo vive en `app.state` de FastAPI: uno por proceso, reemplazable al entrenar y en las pruebas. |
| Repository | La IA no tiene base de datos: solo el backend la usa. |
| Observer para reentrenar | El backend decide cuándo entrenar (cada lunes o un administrador) y llama al endpoint; no hace falta notificar a nadie dentro del servicio. |
