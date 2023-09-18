---
layout: default
title: Integer Overflow y Underflow
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad espacial
nav_order: 3
---

# Integer Overflow y Underflow
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

Se conoce como integer overflow a la acción de intentar guardar un valor
mayor al que una variable de tipo entero puede almacenar. Por otra parte,
integer underflow es el caso contrario, cuando se intenta almacenar un
valor menor al que una variable de tipo entero puede almacenar.

---

## Ejemplo

Integer Overflow
{: .label }

Comencemos con el siguiente código en lenguaje C:

```c
int main() {
  unsigned char num = 255;
}
```

En el código anterior, simplemente declaramos una variable de tipo
unsigned char y le asignamos el valor 255.

Buscando en la documentación de C, podemos encontrar que el tipo de dato
char tiene un tamaño de 1 byte.

Veamos una representación en binario de nuestra variable num:

|1|1|1|1|1|1|1|1|

Podemos observar que nuestro número en binario es 11111111. Recordemos que
el tamaño de un char es de 8 bits, lo que significa que 255 es el número
más grande que podemos almacenar en un tipo de dato char.

Ahora, la pregunta, ¿qué pasaría si intentamos sumar uno a nuestra variable?

Como sabemos, ya están llenos los 8 bits destinados a una variable de tipo
char. Quizá podríamos pensar que pasaría algo similar al buffer overflow, y
que nuestra variable num ahora utilizaría un bit extra, pero no.

Modifiquemos un poco nuestro código para ver lo que realmente sucede:

```c
#include <stdio.h>

int main() {
  unsigned char num = 255;

  printf("%d\n", num);

  num++;

  printf("%d\n", num);
}
```

Veamos la salida del programa para entender qué es lo que pasa al intentar
sobrepasar la cantidad máxima que puede almacenar la variable char:

```
255
0
```

Observamos que después de incrementar el valor de num, obtenemos un cero.
Esto es debido a que solo se guardan los bits menos significativos en
nuestra variable. En este caso, el valor resultante de la suma es 256.
La representación en binario de 256 es la siguiente:

|1|0|0|0|0|0|0|0|0|

Podemos observar que este valor utiliza 9 bits de espacio, por lo que solo
los 8 bits menos significativos se guardan en nuestra variable resultando
en:

|0|0|0|0|0|0|0|0|

Lo cual es un 0, tal y como vimos en la salida del programa.

En este ejemplo se utilizó un tipo de dato unsigned. En tipos de dato
signed, al superar el valor positivo máximo, nuestro número se vuelve
negativo debido a que se utiliza ```complemento a uno``` para representar
números negativos:

```c
#include <stdio.h>

int main() {
  char num = 127;

  printf("%d\n", num);

  num++;

  printf("%d\n", num);
}
```

Salida:

```
127
-128
```

Integer Underflow
{: .label }

Por el otro lado, al intentar restar a la cantidad más pequeña que puede
almacenar un tipo de dato entero obtenemos el efecto contrario:

```c
#include <stdio.h>

int main() {
  unsigned char num = 0;

  printf("%d\n", num);

  num--;

  printf("%d\n", num);
}
```

Salida:

```
0
255
```

