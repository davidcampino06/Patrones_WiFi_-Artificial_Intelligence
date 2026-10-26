#!/usr/bin/env bash
# Builds the Docker image of Railway in GitHub Actions, with retries.
#
# The base image comes from public.ecr.aws. Sometimes the registry refuses the anonymous download for a moment and the
# step failed in 1 to 4 seconds with the code unchanged (the same commit passed when run again). So the build is tried
# up to ATTEMPTS times, waiting a little longer each time, and every failed attempt is written as an annotation with the
# cause: it can be read on the Pull Request page without opening the log.
#
# A real error of the image (a package that does not install, a broken Dockerfile) fails every attempt and still turns
# the check red, with its cause in the annotation.
set -uo pipefail

attempts="${ATTEMPTS:-3}"
wait_seconds="${WAIT_SECONDS:-20}"
tag="${IMAGE_TAG:-wifisense-ai}"
log="$(mktemp)"

for attempt in $(seq 1 "$attempts"); do
  if docker build -t "$tag" . >"$log" 2>&1; then
    tail -n 5 "$log"
    echo "Imagen construida en el intento $attempt de $attempts."
    exit 0
  fi
  cause="$(grep -iE 'error|denied|forbidden|too many|timeout|failed' "$log" | tail -n 2 | tr '\n' ' ' | cut -c1-300)"
  [ -n "$cause" ] || cause="$(tail -n 2 "$log" | tr '\n' ' ' | cut -c1-300)"
  if [ "$attempt" -lt "$attempts" ]; then
    echo "::warning title=Imagen de Railway (intento $attempt de $attempts)::$cause"
    sleep $((attempt * wait_seconds))
  else
    cat "$log"
    echo "::error title=Imagen de Railway::Fallo en los $attempts intentos. Ultima causa: $cause"
  fi
done
exit 1
