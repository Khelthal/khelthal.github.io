---
layout: default
title:  Buffer Overread
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad espacial
nav_order: 2
---


# Buffer Overread
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

A un área en donde se alacena información temporal se le conoce como
un buffer. Naturalmente, está area debe tener un tamaño definido.

Se conoce como buffer overread a un error en el que al intentar leer
información de un buffer, el programa lee información fuera del área
designada para ese buffer.

---

## Ejemplo

Tomemos como ejemplo el siguiente código:

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
  char inputPassword[8];
  char secretPassword[8];

  strcpy(secretPassword, "pass123");
  printf("Ingresa el password\n");

  read(0, inputPassword, 8);

  inputPassword[strcspn(inputPassword, "\n")] = 0;

  if (strcmp(inputPassword, secretPassword) == 0) {
    puts("Credenciales correctas");
  } else {
    printf("El password %s es incorrecto\n", inputPassword);
  }
}
```

Supongamos que solo podemos ejecutar el binario a través de una conexión
remota (no tenemos el código fuente ni el binario). A primera vista, la
única forma de encontrar las credenciales correctas es adivinando.

Veamos la salida que obtenemos al ejecutar el binario.

```
Ingresa el password
admin
El password admin es incorrecto
```

Ahora, recordemos que en lenguaje C los strings arreglos de caracteres
terminados por un null byte. Es decir, al imprimir el contenido de
inputPassword, el programa imprimirá todos los caracteres que encuentre
hasta llegar a un null byte.

En este caso, el programa lee el input con la función read. Una peculiaridad
de esta función es que no agrega un null byte al final del input.

Con esto en mente, intentemos pasarle al programa un string de 8 caracteres.

```
Ingresa el password
12345678
El password 12345678pass123 es incorrecto
```

Al ver la salida vemos el buffer overread. A pesar de que el programa
solo imprime el contenido de la variable inputPassword, logramos hacer
que el programa nos mostrara el contenido de secretPassword también, es
decir, logramos leer fuera de los límites de la variable inputPassword.

## Retos

---

### bor1

¿Podrás superar la barrera que te separa de la flag?

Archivos:

[bor1](../../retos/bor/bor1.zip){: .btn .btn-blue }
