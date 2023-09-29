---
layout: default
title: Position Independent Executable
parent: Mecanismos de Seguridad
nav_order: 4
---

# Position Independent Executable (PIE)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Similar a ASLR, PIE agrega aleatorización a las direcciones de memoria
que son reservadas para nuestro programa. La diferencia es que PIE agrega
aleatorización a las direcciones de memoria de nuestro binario, mientras
que ASLR agrega aleatorización al stack, heap y librerías dinámicas.

---

## Ejemplo

Para entender mejor PIE, veremos un pequeño código en C y analizaremos
la salida del programa sin PIE y con PIE.

Código:

```c
#include <stdlib.h>
#include <stdio.h>

int DATA_VAL = 10;

int main() {
  int val = 5;

  int* data_address = &DATA_VAL;
  void* function_address = main;

  printf(".data address: %p\n", data_address);
  printf("Function address:  %p\n", function_address);
}
```

El código es bastante sencillo, el objetivo es imprimir direcciones de
memoria del binario.

Veamos la salida que obtenemos al ejecutar el programa varias veces:

---

Sin PIE
{: .label .label-purple }

```
$ ./pie_example
.data address: 0x404018
Function address:  0x401126
$ ./pie_example
.data address: 0x404018
Function address:  0x401126
$ ./pie_example
.data address: 0x404018
Function address:  0x401126
```

Como podemos observar, las direcciones donde se reserva la memoria siempre
son las mismas cuando PIE está desactivado.

---

Con PIE
{: .label .label-purple }

```
$ ./pie_example
.data address: 0x558ae2b4f018
Function address:  0x558ae2b4c139
$ ./pie_example
.data address: 0x5581c44c8018
Function address:  0x5581c44c5139
$ ./pie_example
.data address: 0x5557ccb5d018
Function address:  0x5557ccb5a139
```

Aquí podemos ver la aleatorización de PIE en acción. Observamos que las
direcciones de memoria siempre son distintas cada vez que ejecutamos el
binario.
