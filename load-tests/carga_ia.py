"""Prueba de carga del servicio de IA de WiFiSense (solo la librería estándar de Python 3.9+).

Envía a la vez lo mismo que envía el backend con cada medición y cada reporte del agente: detección de anomalías
(ventana de 20 mediciones), calidad de la conexión, auditoría de seguridad y mejor canal. Mide peticiones por segundo,
p50, p95 y p99 por endpoint y termina con código 1 si no cumple el objetivo (p95 menor que 500 ms y menos de 1 % de
errores).

Uso:
    set AI_API_KEY=<la misma clave del backend>      (Linux/Mac: export ...)
    python load-tests/carga_ia.py --url http://localhost:8000 --clientes 10 --segundos 60

La clave se lee solo de la variable de entorno. El servicio de IA no debe estar expuesto a internet (en Railway solo lo
llama el backend por la red privada), así que esta prueba es para correrla en local.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

P95_GOAL_MS = 500.0
ERROR_GOAL = 0.01


def percentile(values: list[float], pct: float) -> float:
    """Percentil por el método del rango más cercano."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-pct * len(ordered) // 100))))
    return ordered[rank - 1]


def window(rng: random.Random, size: int = 20, degraded: bool = False) -> list[dict]:
    """Una ventana de mediciones como la que arma el backend; la última puede venir degradada."""
    start = datetime.now(timezone.utc) - timedelta(minutes=5 * size)
    samples = []
    for i in range(size):
        bad = degraded and i == size - 1
        samples.append({"latency": rng.uniform(250, 400) if bad else rng.uniform(15, 50),
                        "jitter": rng.uniform(40, 80) if bad else rng.uniform(1, 6),
                        "packetLoss": rng.uniform(10, 25) if bad else rng.uniform(0, 0.5),
                        "signalStrength": rng.randint(-65, -45), "connectedDevices": rng.randint(3, 12),
                        "timestamp": (start + timedelta(minutes=5 * i)).isoformat()})
    return samples


def payloads(rng: random.Random) -> list[tuple[str, str, dict]]:
    return [
        ("anomalías", "/api/v1/anomalies/detect",
         {"networkId": rng.randint(1, 50), "simulatedData": False, "measurements": window(rng, degraded=rng.random() < 0.2)}),
        ("calidad", "/api/v1/quality/score",
         {"latencyMs": rng.uniform(10, 120), "jitterMs": rng.uniform(1, 20), "downloadMbps": rng.uniform(5, 300),
          "uploadMbps": rng.uniform(1, 50), "contractedMbps": 200}),
        ("seguridad", "/api/v1/security/assess",
         {"authentication": rng.choice(["WPA2", "WPA3", "WPA"]), "cipher": "CCMP", "openPorts": [53, 80],
          "deviceCount": rng.randint(2, 20), "newDeviceCount": rng.randint(0, 2), "band": "5", "channel": 36,
          "neighborsSameChannel": rng.randint(0, 5)}),
        ("canal", "/api/v1/channel/recommend",
         {"band": "2.4", "channel": 6, "channelCounts": [{"channel": c, "networks": rng.randint(0, 8)} for c in (1, 6, 11)]}),
    ]


def call(base: str, key: str, path: str, body: dict) -> tuple[int, float]:
    request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-API-Key": key})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=15) as answer:
            answer.read()
            return answer.status, (time.perf_counter() - start) * 1000
    except urllib.error.HTTPError as error:
        return error.code, (time.perf_counter() - start) * 1000
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0, (time.perf_counter() - start) * 1000


def client(base: str, key: str, until: float, times: dict, errors: dict, lock: threading.Lock) -> None:
    rng = random.Random()
    while time.time() < until:
        name, path, body = rng.choice(payloads(rng))
        status, ms = call(base, key, path, body)
        with lock:
            times[name].append(ms)
            if status != 200:
                errors[name] += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prueba de carga del servicio de IA de WiFiSense.")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--clientes", type=int, default=10, help="peticiones simultáneas")
    parser.add_argument("--segundos", type=int, default=60)
    parser.add_argument("--salida", help="guardar el resultado en este archivo JSON")
    args = parser.parse_args(argv)
    base, key = args.url.rstrip("/"), os.environ.get("AI_API_KEY", "")

    times: dict[str, list[float]] = defaultdict(list)
    errors: dict[str, int] = defaultdict(int)
    lock = threading.Lock()
    print(f"Probando {base} con {args.clientes} clientes durante {args.segundos} s…")
    start = time.time()
    threads = [threading.Thread(target=client, args=(base, key, start + args.segundos, times, errors, lock), daemon=True)
               for _ in range(args.clientes)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=args.segundos + 30)
    seconds = time.time() - start

    rows, everything = [], []
    print(f"\n{'Endpoint':12} {'Peticiones':>10} {'Errores':>8} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
    for name in sorted(times):
        everything += times[name]
        row = {"endpoint": name, "peticiones": len(times[name]), "errores": errors[name],
               "p50_ms": round(percentile(times[name], 50), 1), "p95_ms": round(percentile(times[name], 95), 1),
               "p99_ms": round(percentile(times[name], 99), 1)}
        rows.append(row)
        print(f"{name:12} {row['peticiones']:>10} {row['errores']:>8} {row['p50_ms']:>8} {row['p95_ms']:>8} {row['p99_ms']:>8}")
    total, failed = len(everything), sum(errors.values())
    result = {"segundos": round(seconds, 1), "clientes": args.clientes, "peticiones": total,
              "por_segundo": round(total / seconds, 1) if seconds else 0.0,
              "tasa_errores": round(failed / total, 4) if total else 0.0,
              "p95_ms": round(percentile(everything, 95), 1), "endpoints": rows}
    ok = total > 0 and result["p95_ms"] < P95_GOAL_MS and result["tasa_errores"] < ERROR_GOAL
    print(f"\nTotal: {total} peticiones = {result['por_segundo']} por segundo; errores "
          f"{result['tasa_errores'] * 100:.2f} %; p95 {result['p95_ms']} ms")
    print("RESULTADO:", "CUMPLE" if ok else "NO CUMPLE", f"(objetivo: p95 < {P95_GOAL_MS:.0f} ms y errores < 1 %)")
    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as out:
            json.dump({**result, "cumple": ok}, out, ensure_ascii=False, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
