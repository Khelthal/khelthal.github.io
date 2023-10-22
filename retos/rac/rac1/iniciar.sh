#!/bin/bash

NOMBRE_CONTENEDOR="rac1"

if ! command -v nc &> /dev/null
then
  echo "No se encontró nc (netcat) en el sistema."
  exit 1
fi

if ! command -v docker &> /dev/null
then
  echo "No se encontró docker en el sistema."
  exit 1
fi

echo "Preparando contenedor..."
docker build . -t "$NOMBRE_CONTENEDOR" &> /dev/null && echo "Listo" || (echo "Error"; exit 1)

echo "Ejecutando instancia del contenedor..."
docker run -d --name $NOMBRE_CONTENEDOR $NOMBRE_CONTENEDOR &> /dev/null && echo "Listo" || (echo "Error"; exit 1)

echo "Copiando ejecutable..."
docker cp $NOMBRE_CONTENEDOR:/chal/chal . && echo "Listo" || (echo "Error"; exit 1)

IP_CONTENEDOR=$(docker inspect --format='{{.NetworkSettings.IPAddress}}' $NOMBRE_CONTENEDOR)

echo "Ya puedes conectarte al reto"
echo ""
echo "nc $IP_CONTENEDOR 1337"
