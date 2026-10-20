# Pruebas de carga del servicio de IA

`load-tests/carga_ia.py` envía a la vez lo mismo que envía el backend: detección de anomalías con una ventana de 20
mediciones (el 20 % con la última degradada), calidad de la conexión, auditoría de seguridad y mejor canal. Solo usa la
librería estándar de Python. Objetivo: **p95 menor que 500 ms y menos de 1 % de errores** (código de salida 0 o 1).

```cmd
set AI_API_KEY=<la misma clave del backend>
python load-tests\carga_ia.py --url http://localhost:8000 --clientes 10 --segundos 60 --salida resultado.json
```

En Railway el servicio de IA solo lo llama el backend por la red privada; esta prueba es para correrla en local.

## Resultados (local, 19/10/2026, 2 núcleos)

Un solo proceso de uvicorn, como en Railway.

| Peticiones a la vez | Por segundo | Errores | Anomalías p50 / p95 | Calidad, canal y seguridad p95 | p95 total | ¿Cumple? |
|---|---:|---:|---:|---:|---:|---|
| 5 | 70 | 0 % | 185 / 262 ms | 64–66 ms | 227 ms | Sí |
| 10 | 72 | 0 % | 313 / 458 ms | 138–149 ms | 382 ms | Sí |
| 20 (estrés) | 71 | 0 % | 541 / 752 ms | 295–308 ms | 650 ms | No |

**Capacidad: unas 70 peticiones por segundo.** Cada reporte de un sensor pide como mucho 4 veredictos cada 5 minutos,
o sea menos de 0,02 peticiones por segundo por sensor: el servicio alcanza para miles de sensores. Con 20 peticiones
llegando exactamente al mismo tiempo, todas esperan su turno y el p95 pasa de 500 ms; nada falla.

## Mejora que salió de la prueba

La primera corrida con 20 clientes daba **44 peticiones por segundo** y la detección tardaba 975 ms (p50). El perfil
mostró que cada detección recorría los 200 árboles del Isolation Forest **dos veces**: una para el puntaje y otra para
decidir si era anómala (`predict`). Ahora la decisión sale del mismo puntaje (`AnomalyDetectionService.outliers`, con
una prueba que comprueba que da exactamente lo mismo que `predict`). Resultado: **71 peticiones por segundo (+60 %)** y
la detección en 541 ms (p50) con la misma carga.

## Por qué un solo proceso

Varios procesos de uvicorn (`--workers`) atenderían más peticiones a la vez, pero cada uno tendría su propio modelo: al
entrenar con datos reales solo cambiaría el modelo de uno de ellos. Mientras el uso real esté tan por debajo de la
capacidad, un solo proceso es lo correcto.

## Límite del tamaño de las solicitudes

Desde este avance el servicio rechaza con `413` cualquier solicitud de más de 8 MB antes de leerla (`BodyLimit` en
`app/main.py`): la más grande que es legítima es un entrenamiento de 20 000 mediciones (unos 4 MB). Así nadie puede
hacer que el servicio guarde en memoria una solicitud enorme.
