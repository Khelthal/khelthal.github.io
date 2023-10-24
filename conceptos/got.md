---
layout: default
title: Global Offset Table
parent: Conceptos
nav_order: 4
---

# Global Offset Table (GOT)
{: .no_toc }

## Conocimientos necesarios
{: .no_toc .text-delta }

Antes de comenzar con esta sección, es recomendable que leas las siguientes
secciones de la guía si aún no las has leído:

[Procedure Linkage Table](../../conceptos/plt.html){: .btn .btn-green }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Cuando utilizamos librerías dinámicas, es imposible conocer en tiempo de
compilación la dirección de estas funciones.

Retomemos el ejemplo que utilizamos en plt:

```c
#include <stdio.h>

int main() {
  puts("Esta funcion no fue declarada en este codigo");
  printf("Esta funcion %d tampoco\n", 2);
}
```

Utilicemos el comando lld para ver las librerías dinámicas que utiliza
nuestro binario:

```
$ ldd test
        linux-vdso.so.1 (0x00007ffe28d7d000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007fe19f37d000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fe19f57b000)
$ ldd test
        linux-vdso.so.1 (0x00007ffe28929000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f0fb176e000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f0fb196c000)
$ ldd test
        linux-vdso.so.1 (0x00007ffca4241000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f1adf7f2000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f1adf9f0000)
$ ldd test
        linux-vdso.so.1 (0x00007ffeda578000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f2e84418000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f2e84616000)
```

Observamos que la dirección en la que se guarda libc en memoria cambia cada
vez que ejecutamos el comando. Este cambio es lo que hace imposible
"hardcodear" las direcciones de las funciones de libc en el binario.

La global offset table existe para guardar las direcciones reales de las
funciones de librerías dinámicas, estas direcciones son obtenidas durante
la ejecución del programa.

Podemos usar el comando readelf para inspeccionar la global offset table:

```
$ readelf -r test
...

Relocation section '.rela.plt' at offset 0x640 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000004000  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000004008  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
```
