#!/bin/bash

NOMBRE_CONTENEDOR="rac1"

if ! command -v docker &> /dev/null
then
  echo "No se encontró docker en el sistema."
  exit 1
fi

docker stop "$NOMBRE_CONTENEDOR" &> /dev/null
docker rm $NOMBRE_CONTENEDOR &> /dev/null
docker image rm $NOMBRE_CONTENEDOR &> /dev/null