---
layout: default
title: Address Space Layout Randomization
parent: Mecanismos de Seguridad
nav_order: 1
---

# Address Space Layout Randomization (ASLR)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

ASLR es un mecanismo integrado en el sistema operativo que implementa
aleatoriedad al momento de reservar memoria para los procesos.

---

## Ejemplo

Para entender mejor ASLR, veremos un pequeño código en C y analizaremos
la salida del programa sin ASLR y con ASLR.

Código:

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  int val = 5;

  int* stack_address = &val;
  void* heap_address = malloc(128);
  void* libc_address = puts;

  printf("Stack address: %p\n", stack_address);
  printf("Heap address:  %p\n", heap_address);
  printf("Libc address:  %p\n", libc_address);
}
```

El código es bastante sencillo, el objetivo es imprimir una dirección de
memoria del stack, una del heap y una de una librería dinámica, en este
caso, la librería de C.

Veamos la salida que obtenemos al ejecutar el programa varias veces:

---

Sin ASLR
{: .label .label-purple }

```
$ ./aslr_example
Stack address: 0x7fffffffe7fc
Heap address:  0x5555555592a0
Libc address:  0x7ffff7e3ce60
$ ./aslr_example
Stack address: 0x7fffffffe7fc
Heap address:  0x5555555592a0
Libc address:  0x7ffff7e3ce60
$ ./aslr_example
Stack address: 0x7fffffffe7fc
Heap address:  0x5555555592a0
Libc address:  0x7ffff7e3ce60
```

Como podemos observar, las direcciones donde se reserva la memoria siempre
son las mismas cuando ASLR está desactivado.

---

Con ASLR
{: .label .label-purple }

```
$ ./aslr_example
Stack address: 0x7fff2c7372ac
Heap address:  0x56073ca7b2a0
Libc address:  0x7fd0483fbe60
$ ./aslr_example
Stack address: 0x7ffc60312a7c
Heap address:  0x56310b6482a0
Libc address:  0x7f146e343e60
$ ./aslr_example
Stack address: 0x7fff2061d94c
Heap address:  0x55ab1a5362a0
Libc address:  0x7f74af50ee60
```

Aquí podemos ver la aleatorización de ASLR en acción. Observamos que las
direcciones de memoria siempre son distintas cada vez que ejecutamos el
binario.

---

## Mitiga

Este mecanismo mitiga los siguientes tipos de errores y tipos de explotación:

[Return To Libc](../../tipos_explotacion/control/ret2libc.html){: .btn .btn-green }

Por lo que probablemente sea mejor intentar otras técnicas contra binarios
que tengan esta protección activada.