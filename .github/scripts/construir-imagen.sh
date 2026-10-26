#!/usr/bin/env bash
# Builds the Docker image of Railway in GitHub Actions.
#
# The base image is the official Python image. Its default registry, public.ecr.aws, limits anonymous downloads per
# address, and the GitHub machines share addresses: the check failed with "429 Too Many Requests - toomanyrequests:
# Data limit exceeded" while the code was fine. So the check first downloads the SAME official image from Google's
# mirror of Docker Hub (mirror.gcr.io) and falls back to public.ecr.aws; each round is retried after a wait. Railway is
# not affected by this script: it builds with the Dockerfile as it is.
#
# Every failed attempt is written as an annotation with its cause, readable on the Pull Request page. A real error of
# the image (a package that does not install, a broken Dockerfile) fails with every registry and turns the check red.
set -uo pipefail

default_image="$(sed -n 's/^ARG PYTHON_IMAGE=//p' Dockerfile | head -n 1)"
if [ -z "$default_image" ]; then
  echo "::error title=Imagen de Railway::El Dockerfile no declara ARG PYTHON_IMAGE"
  exit 1
fi
mirror_image="mirror.gcr.io/library/${default_image##*/}"
images="${BASE_IMAGES:-$mirror_image $default_image}"
rounds="${ROUNDS:-3}"
wait_seconds="${WAIT_SECONDS:-20}"
tag="${IMAGE_TAG:-wifisense-ai}"
log="$(mktemp)"
cause=""

for round in $(seq 1 "$rounds"); do
  for image in $images; do
    if docker build --build-arg "PYTHON_IMAGE=$image" -t "$tag" . >"$log" 2>&1; then
      tail -n 5 "$log"
      echo "Imagen construida con $image (ronda $round de $rounds)."
      exit 0
    fi
    cause="$(grep -iE 'error|denied|forbidden|too many|timeout|failed' "$log" | tail -n 2 | tr '\n' ' ' | cut -c1-300)"
    [ -n "$cause" ] || cause="$(tail -n 2 "$log" | tr '\n' ' ' | cut -c1-300)"
    echo "::warning title=Imagen de Railway con $image (ronda $round de $rounds)::$cause"
  done
  [ "$round" -lt "$rounds" ] && sleep $((round * wait_seconds))
done
cat "$log"
echo "::error title=Imagen de Railway::Fallo con todos los registros en $rounds rondas. Ultima causa: $cause"
exit 1
