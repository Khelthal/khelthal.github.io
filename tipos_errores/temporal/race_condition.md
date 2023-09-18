---
layout: default
title: Race Condition
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad temporal
nav_order: 3
---

# Race Condition
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Una race condition es un tipo de error que surge cuando existe un
intervalo de tiempo entre un mecanismo de seguridad y una operación.

---

## Ejemplo

Un ejemplo clásico de race condition es una cuenta bancaria en donde
podemos retirar dinero.

Veamos el siguiente código:

```c
#include <stdio.h>
#include <unistd.h>

int dineroCuenta = 1000;

int retirarDinero(int cantidad) {
  if (dineroCuenta >= cantidad) {
    sleep(1);
    dineroCuenta -= cantidad;
    return cantidad;
  }

  return 0;
}

int main() {
  int dineroRetirado = 0;

  dineroRetirado += retirarDinero(1000);
  dineroRetirado += retirarDinero(1000);

  printf("El dinero retirado fue: %d\n", dineroRetirado);
}
```

Veamos la salida que obtenemos al ejecutar el binario:

```
El dinero retirado fue: 1000
```

Pero, ¿qué pasaría si la función retirarDinero pudiera correr en paralelo?.
Vemos que la función retirarDinero verifica que el dinero en la cuenta
sea suficiente, pero tarda 1 segundo en restar el dinero retirado de la
cuenta.

```c
int retirarDinero(int cantidad) {
  if (dineroCuenta >= cantidad) { // Segundo 0, el dinero en la cuenta es suficiente
    sleep(1);
    dineroCuenta -= cantidad;     // Segundo 1, ¿el dinero en la cuenta sigue siendo suficiente?
    return cantidad;
  }

  return 0;
}
```

Veamos qué pasaría si utilizamos hilos para retirar dinero (simulando el
retiro de dinero desde dos cajeros diferentes al mismo tiempo).

Código con hilos:

```c
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define THREADS_COUNT 2

int dineroCuenta = 1000;

void *retirarDinero(void *args) {
  int cantidad = ((int *)args)[1];
  int *dineroRetirado = &((int *)args)[0];

  if (dineroCuenta >= cantidad) {
    sleep(1);
    dineroCuenta -= cantidad;
    *dineroRetirado += cantidad;
  }

  pthread_exit(NULL);
}

int main() {
  int dinero[2];
  dinero[0] = 0; // Dinero retirado
  dinero[1] = 1000; // Cantidad a retirar

  pthread_t threads[THREADS_COUNT];

  for (int i = 0; i < THREADS_COUNT; i++) {
    pthread_create(&threads[i], NULL, retirarDinero, dinero);
  }

  for (int i = 0; i < THREADS_COUNT; i++) {
    pthread_join(threads[i], NULL);
  }

  printf("El dinero retirado fue: %d\n", dinero[0]);
}
```

Veamos la salida que obtenemos:

```
El dinero retirado fue: 2000
```

Observamos que gracias a la race condition logramos retirar más dinero
del que había en la cuenta bancaria.