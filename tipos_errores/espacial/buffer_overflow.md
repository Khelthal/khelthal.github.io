---
layout: default
title: Buffer Overflow
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad espacial
nav_order: 1
---

# Buffer Overflow
{: .no_toc }

## Conocimientos necesarios
{: .no_toc .text-delta }

Antes de comenzar con esta sección, es recomendable que leas las siguientes
secciones de la guía si aún no las has leído:

[Stack](../../conceptos/stack.html){: .btn .btn-green }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

A un área en donde se almacena información temporal se le conoce como
un buffer. Naturalmente, esta área debe tener un tamaño definido.

Se conoce como buffer overflow a un error en el que la información
almacenada supera el tamaño del área designada para guardar esa información.
Cuando esto sucede, la información rebasa los límites de su área designada,
afectando de áreas vecinas.

---

## Ejemplo

Pongamos el siguiente código en C como ejemplo:

```c
int main() {
  char buff1[8];
  char buff2[8];
}
```

En este código en lenguaje C, tenemos 2 buffers, cada uno con un
tamaño de 8 bytes (Es un arreglo de char. El tipo de dato char tiene un
tamaño de 1 byte).

Modifiquemos un poco el código para guardar algunos caracteres en nuestros
buffers.

```c
#include <string.h>
#include <stdio.h>

int main() {
  char buff1[8];
  char buff2[8];

  strcpy(buff1, "string1");
  strcpy(buff2, "string2");

  puts(buff1);
  puts(buff2);
}
```

En esta versión copiamos dos strings diferentes a cada buffer y después
imprimimos los contenidos. Cada string tiene un tamaño de 8 caracteres
(tomando en cuenta el null byte), por lo que no sobrepasan el tamaño
de los buffers.

Veamos la salida que obtenemos al ejecutar este código:

```
string1
string2
```

Hasta el momento la salida es la esperada.

Ahora modifiquemos el código anterior para intentar copiar un string
que sobrepase el tamaño del buffer.

```c
#include <string.h>
#include <stdio.h>

int main() {
  char buff1[8];
  char buff2[8];

  strcpy(buff1, "string1");
  strcpy(buff2, "string2");

  puts(buff1);
  puts(buff2);

  strcpy(buff1, "esto_no_cabe_aa");

  puts(buff1);
  puts(buff2);
}
```

Nótese que después de imprimir buff1 y buff2, el único buffer que se alteró
fue buff1.

Podríamos pensar que después de estos cambios la salida del programa sería algo
como:

```
string1
string2
esto_no_cabe_aa
string2
```

Sin embargo, al ejecutar el programa, la salida que obtenemos es la
siguiente:

```
string1
string2
esto_no_cabe_aa
cabe_aa
```

A pesar de que nunca modificamos la variable buff2, al momento de imprimir su
contenido, vemos que ya no es "string2". Esto es debido al buffer overflow.
Debido a que no había suficiente espacio en buff1, el programa siguió
copiando caracteres en áreas de memoria que ya no correspondían a buff1.
En este caso, los caracteres sobrantes afectaron al área designada para
buff2.

Veamos una aproximación de cómo se vería el stack antes de modificar la variable
buff1.


| Nombres        | Stack       |
|:---------------|:------------|
| buff1          | 0x69727473  |
| buff1          | 0x0031676e  |
| buff2          | 0x69727473  |
| buff2          | 0x0032676e  |
| ebp guardado   | ?           |
| return address | ?           |

Podemos ver que buff1 y buff2 están juntos en el stack. Es por eso que
al intentar copiar un string de más de 8 caracteres a buff1 modificamos
el valor de buff2.

Veamos el stack después de modificar buff1.

| Nombres        | Stack       |
|:---------------|:------------|
| buff1          | 0x6f747365  |
| buff1          | 0x5f6f6e5f  |
| buff2          | 0x65626163  |
| buff2          | 0x0061615f  |
| ebp guardado   | ?           |
| return address | ?           |

---

## Mitigaciones
Los siguientes mecanismos de seguridad dificultan o impiden el uso de esta
técnica:

[Canary](../../mecanismos_seguridad/canary.html){: .btn .btn-green }
[PIE](../../mecanismos_seguridad/pie.html){: .btn .btn-green }


## Retos

---

### bof1

¿Recuerdas para qué sirve el return address en el stack?

Explota el buffer overflow en este reto para lograr ejecutar la función
win.

Archivos:

[bof1](../../retos/bof/bof1.zip){: .btn .btn-blue }
