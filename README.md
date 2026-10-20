# WiFiSense-ai

Servicio independiente de detección de anomalías en redes Wi-Fi. Lo llama **solo el backend**: no recibe
peticiones del navegador y no accede a la base de datos; analiza exactamente los datos que el backend le envía.

## Tecnologías

Python 3.13 · FastAPI · Pydantic v2 · NumPy · Pandas · scikit-learn (Isolation Forest; LOF y One-Class SVM para
comparar) · joblib · Uvicorn · pytest

## Estructura

```text
app/main.py           endpoints, carga del modelo al arrancar, API key
app/schemas.py        contrato de entrada/salida (JSON en camelCase)
app/preprocessing.py  orden cronológico, imputación, transformación logarítmica, desviación robusta
app/model_service.py  entrenamiento, persistencia, detección, severidad y explicación
app/diagnosis.py      causa probable de la anomalía (firmas de cada falla)
app/scenarios.py      escenarios de fallas simuladas y etiquetadas para evaluar
app/evaluation.py     comparación IF vs LOF vs One-Class SVM, ajuste y sensibilidad del umbral
app/quality.py        calidad de una conexión de 0 a 100 (curvas por métrica, actividades y consejos)
app/security.py       auditoría de seguridad de la red del usuario (cifrado, puertos del router, equipos nuevos)
app/channel.py        mejor canal Wi-Fi según las redes vecinas que vio el agente
app/training.py       entrenamiento con mediciones reales y decisión de reemplazar el modelo en uso
app/llm_advisor.py    recomendaciones opcionales con Claude
docs/                 evaluacion_modelos.md, entrenamiento_real.md, pruebas_de_carga.md, modelo_calidad.md, auditoria_seguridad.md y canal_wifi.md
load-tests/           carga_ia.py: prueba de carga del servicio (solo Python estándar)
tests/                preprocesamiento, modelo, diagnóstico, escenarios, evaluación, seguridad, canal, agente y API
agent/                agente WiFiSense que corre en la casa del usuario e instalador para Windows (ver agent/README.md)
.github/workflows/    servicio-ia.yml (pruebas, pip-audit e imagen en cada Pull Request) y agente-windows.yml (instalador)
.github/dependabot.yml  actualizaciones mensuales de pip, acciones y Docker
```

## Modelo

**Isolation Forest** aísla puntos con cortes aleatorios; los puntos anómalos se aíslan con menos cortes. Se eligió
porque:

- es **no supervisado**: no existen anomalías etiquetadas de redes reales para entrenar un clasificador;
- funciona bien con pocas variables numéricas y es rápido de entrenar y de consultar;
- su puntaje normalizado `s(x) ∈ (0, 1)` es interpretable: cerca de 1 = anómalo.

**Hiperparámetros:** 200 árboles, cada uno con toda la línea base (`max_samples=1.0`), y contaminación de 2 %.
Se eligieron en un conjunto de validación (ver *Evaluación*).

**Entrenamiento.** Al arrancar, si no existe el archivo de `AI_MODEL_PATH` (o es de otra versión), se entrena con una línea base
**sintética** de redes sanas (5 000 muestras generadas en `generate_baseline`) y se guarda con joblib. Es una
decisión honesta y explícita: no hay datos reales etiquetados. `GET /api/v1/model` lo declara en `trainedOn`.

**Entrenamiento con datos reales (Avance 16).** Con las mediciones reales de los sensores y agentes que envía el
backend (`POST /api/v1/model/train`), se entrena un modelo nuevo y se compara con el que está en uso; solo lo
reemplaza si es mejor, y el archivo guardado conserva el nombre de la versión real. Ver
[docs/entrenamiento_real.md](docs/entrenamiento_real.md).

**Variables:** `latency`, `jitter`, `packet_loss`, `bandwidth`, `signal_strength`, `traffic_volume`,
`connected_devices`, `packet_count`.

**Preprocesamiento.** Orden por timestamp, imputación con la mediana de la línea base (las variables imputadas se
devuelven en `imputedFeatures`), `log1p` sobre variables de cola larga.

**Decisión.** Se evalúa la **última** medición de la ventana. Es anómala si el bosque la marca como outlier
(contaminación 2 %). Severidad según la distancia al umbral: `LOW` < 0.08 ≤ `MEDIUM` < 0.17 ≤ `HIGH`.
`featureDeviations` trae la desviación robusta de cada variable, con signo tal que positivo siempre es peor (más
latencia, menos señal…); `contributingFeatures` lista las que pasan de 2.

## Diagnóstico de la causa

Isolation Forest dice *que* una medición es rara, no *por qué*. `app/diagnosis.py` compara las desviaciones con la
firma de cada falla y devuelve `anomalyType`, `diagnosis` (explicación) y una recomendación concreta:

| `anomalyType` | Firma |
|---|---|
| `CONGESTION` | más dispositivos y tráfico, con latencia y jitter altos |
| `INTERFERENCE` | pérdida de paquetes y jitter altos con buena señal |
| `WEAK_COVERAGE` | señal débil, menos ancho de banda y pérdidas |
| `PROVIDER_ISSUE` | latencia alta y poco ancho de banda con la red local normal |
| `SUSPICIOUS_TRAFFIC` | muchos más paquetes sin más dispositivos (escaneo, inundación, descarga masiva) |
| `UNKNOWN` | ninguna firma coincide lo suficiente |

## Evaluación

`app/evaluation.py` compara **Isolation Forest**, **Local Outlier Factor** y **One-Class SVM** con los mismos datos:
entrenan con la línea base sana y se prueban con 2 000 mediciones sanas y 500 con fallas simuladas de intensidad
aleatoria (`app/scenarios.py`, otra semilla). Mide precisión, recall, F1, falsas alarmas, ROC-AUC, recall por tipo de
falla y tiempos; además ajusta Isolation Forest en un conjunto de validación aparte, mide la sensibilidad del umbral
y el acierto del diagnóstico. Resultados y conclusiones: [docs/evaluacion_modelos.md](docs/evaluacion_modelos.md).

| Algoritmo | F1 | Falsas alarmas | ROC-AUC |
|---|---|---|---|
| **Isolation Forest** (producción) | 0,898 | 1,9 % | 0,978 |
| Local Outlier Factor | 0,897 | 1,8 % | 0,977 |
| One-Class SVM | 0,887 | 3,2 % | 0,977 |

El servicio calcula el informe en segundo plano al arrancar (unos segundos) y lo entrega en
`GET /api/v1/model/evaluation`; mientras tanto responde 503. Los datos son simulados y el informe lo dice.

## Calidad de la conexión

`POST /api/v1/quality/score` califica una prueba de conexión (la del usuario final en Mi Wi-Fi) o una medición de
una red monitoreada. Cada métrica recibe un puntaje de 0 a 100 con una curva basada en lo que piden los servicios
comunes; el total es el promedio ponderado, pero una métrica muy mala lo limita (puntaje de la peor + 30). Con la
velocidad contratada, la bajada se juzga como porcentaje de lo contratado. La respuesta dice para qué alcanza la
conexión (navegar, videollamadas, video HD y 4K, juegos en línea) y hasta dos consejos en español. Detalle de las
curvas y sus fuentes: [docs/modelo_calidad.md](docs/modelo_calidad.md).

| Puntaje | Calificación |
|---|---|
| 85–100 | `EXCELLENT` (Excelente) |
| 70–84 | `GOOD` (Buena) |
| 50–69 | `FAIR` (Regular) |
| 0–49 | `POOR` (Mala) |

## Auditoría de seguridad

`POST /api/v1/security/assess` revisa lo que el agente WiFiSense vio en la red del usuario: tipo de cifrado del
Wi-Fi, puertos abiertos en el router, dispositivos nuevos, banda y saturación del canal. Cada hallazgo resta puntos
y trae qué significa y qué hacer, en español. Un hallazgo crítico (red abierta, WEP) deja el puntaje en 39 o menos y
uno alto (WPA/TKIP, Telnet, SMB) en 64 o menos. Reglas completas: [docs/auditoria_seguridad.md](docs/auditoria_seguridad.md).

| Puntaje | Calificación |
|---|---|
| 85–100 | `SECURE` (Segura) |
| 65–84 | `ACCEPTABLE` (Aceptable) |
| 40–64 | `AT_RISK` (En riesgo) |
| 0–39 | `CRITICAL` (Crítica) |

## Mejor canal Wi-Fi

`POST /api/v1/channel/recommend` recibe el canal y la banda del router y cuántos puntos de acceso vecinos vio el
agente en cada canal (`channelCounts`). Para cada canal recomendable (1, 6 y 11 en 2,4 GHz; los que no usan radar en
5 GHz) suma la interferencia: un vecino en el mismo canal cuenta 1 y uno en un canal encimado cuenta menos (en
2,4 GHz baja de a 0,2 por cada canal de distancia; en 5 GHz, 0,5 si está en el mismo bloque de 80 MHz). Recomienda
cambiar solo si el nuevo canal tiene al menos una red interfiriendo menos (o si el router está en un canal de
2,4 GHz que pisa a dos de los buenos), porque cambiar desconecta a todos unos segundos. Detalle:
[docs/canal_wifi.md](docs/canal_wifi.md).

## Recomendaciones con Claude (opcional)

Si se define `ANTHROPIC_API_KEY`, después de la detección `ClaudeAdvisor` (`app/llm_advisor.py`) pide a Claude
hasta 3 recomendaciones en español (le envía también la causa probable del diagnóstico) y reemplaza la recomendación por reglas. La respuesta indica el origen en
`recommendationSource` (`CLAUDE` o `RULES`).

- Modelo por defecto: `claude-haiku-4-5-20251001` (cambiable con `CLAUDE_MODEL`).
- Solo se envían métricas agregadas y el veredicto del modelo; nunca IP, MAC, nombres de usuario ni identificadores.
- Si la API falla, se agota la cuota o no hay clave, se usa la recomendación por reglas y el análisis no se interrumpe.
- La API de Claude se paga aparte en la Consola de Claude; una suscripción Claude Pro no la incluye.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health` | Estado del servicio (público) |
| GET | `/api/v1/model` | Algoritmo, versión, variables, umbral y origen del entrenamiento |
| GET | `/api/v1/model/evaluation` | Comparación de algoritmos, ajuste, sensibilidad y diagnóstico |
| POST | `/api/v1/model/train` | Entrena con mediciones reales (mínimo 300), compara con el modelo en uso y lo reemplaza solo si es mejor; `restore: true` reconstruye una versión ya aprobada |
| POST | `/api/v1/anomalies/detect` | Detecta anomalías en una ventana de mediciones |
| POST | `/api/v1/quality/score` | Calidad de 0 a 100 de una prueba o medición |
| POST | `/api/v1/security/assess` | Auditoría de seguridad de 0 a 100 con hallazgos y acciones |
| POST | `/api/v1/channel/recommend` | Canal con menos interferencia y si vale la pena cambiarlo |

Si `AI_API_KEY` está definida, los endpoints `/api/v1/**` exigen la cabecera `X-API-Key` (comparada en tiempo
constante). Una solicitud de más de 8 MB se rechaza con 413 antes de leerla.

**Capacidad** ([docs/pruebas_de_carga.md](docs/pruebas_de_carga.md)): unas 70 peticiones por segundo en 2 núcleos, con
10 a la vez p95 de 382 ms. Cada detección recorre los 200 árboles una sola vez (antes dos): +60 % de capacidad.

### Entrada

```json
{
  "networkId": 3,
  "simulatedData": true,
  "measurements": [
    { "latency": 74.1, "jitter": 21.3, "packetLoss": 4.2, "bandwidth": 41.0, "signalStrength": -74,
      "trafficVolume": 220.5, "connectedDevices": 66, "packetCount": 180000, "timestamp": "2026-10-05T22:00:00Z" }
  ]
}
```

Entre 1 y 1 000 mediciones. `latency`, `jitter` y `packetLoss` son obligatorios; el resto es opcional.

### Salida

```json
{
  "anomalyDetected": true,
  "anomalyScore": 0.7103,
  "severity": "HIGH",
  "anomalyType": "CONGESTION",
  "diagnosis": "Causa probable: congestión de la red. Hay más dispositivos y tráfico de lo habitual, y la latencia sube con ellos.",
  "message": "Posible congestión de la red: pérdida de paquetes, dispositivos conectados, jitter",
  "recommendation": "Distribuye los clientes entre puntos de acceso, limita el ancho de banda por cliente o agrega capacidad en la zona.",
  "recommendationSource": "RULES",
  "contributingFeatures": ["packet_loss", "connected_devices", "jitter"],
  "featureDeviations": { "latency": 1.8, "jitter": 3.1, "packet_loss": 9.6, "bandwidth": 0.9, "signal_strength": -0.2,
                         "traffic_volume": 1.4, "connected_devices": 5.2, "packet_count": 0.1 },
  "anomalousSamples": 50,
  "sampleSize": 50,
  "imputedFeatures": [],
  "modelVersion": "isolation-forest-1.1",
  "simulatedData": true
}
```

`simulatedData` se devuelve tal como llegó: el resultado nunca oculta que los datos eran simulados.

## Ejecución

```bash
pip install -r requirements.txt
cp .env.example .env                       # AI_API_KEY igual a la del backend
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --port 8000
pytest                                     # 239 pruebas (2 solo corren en Windows)
python load-tests/carga_ia.py --clientes 10  # prueba de carga (AI_API_KEY en el entorno)
python -m app.evaluation                   # imprime la evaluación en Markdown
docker build -t wifisense-ai . && docker run -p 8000:8000 -e AI_API_KEY=... wifisense-ai
```

## Integración con el backend

`AnomalyDetectionStrategy` (WiFiSense-backend) arma la ventana con las últimas 50 mediciones de la red, cruza el
tráfico por timestamp y llama a `POST /api/v1/anomalies/detect` mediante `AiAnalysisClient`. El backend guarda la
respuesta en `ai_predictions`, actualiza el estado de la red y genera alertas si corresponde.

El agente (`agent/`) también es el **sensor de las redes del equipo**: con un código del panel, sus reportes llegan al
backend como mediciones reales de esa red (fuente `AGENT`), con el tráfico del computador y sus paquetes por protocolo,
y el backend corre sobre ellas el mismo análisis por umbrales del monitoreo. Con cada reporte del sensor el backend
pide también la auditoría de seguridad, la calidad y el mejor canal (los mismos endpoints de Mi Wi-Fi), y el panel
muestra los equipos conectados de esa red. Desde 1.6.0 un computador puede medir varias redes: cada código queda ligado a su Wi-Fi y el agente usa
la clave del Wi-Fi en el que está. El instalador (1.5.0 reinstala aunque el agente esté en marcha) se prueba en
Windows real en cada Pull Request que cambie el agente (`.github/workflows/agente-windows.yml`) y se publica al llegar a
`main`. Desde 1.7.0 el agente reconoce el tipo de cada equipo (mDNS, UPnP y servicios), marca su propio computador
y el router, reporta cada minuto mientras el usuario identifica un equipo y se actualiza sin código.

El backend entrena el modelo con las mediciones reales cada semana (o cuando un administrador lo pide) y guarda cada
versión con sus métricas en `ai_model_versions`; si este servicio se redespliega, el backend le reconstruye la
versión activa.

## Pendiente

Variables que separen la red local de internet, fallas reales etiquetadas por el equipo para medir con ellas (hoy las
fallas de prueba se simulan sobre las mediciones reales), clasificador supervisado del tipo de falla para comparar con
las firmas, y explicaciones con SHAP.
