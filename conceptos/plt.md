---
layout: default
title: Procedure Linkage Table
parent: Conceptos
nav_order: 3
---

# Procedure Linkage Table (PLT)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

La procedure linkage table, de forma simplificada, se encarga de almacenar
funciones que provienen de librerías dinámicas en el binario.

Tomemos como ejemplo el siguiente código:

```c
#include <stdio.h>

int main() {
  puts("Esta funcion no fue declarada en este codigo");
  printf("Esta funcion %d tampoco\n", 2);
}
```

Utilicemos objdump para buscar las funciones puts y printf en el binario
generado:

```
$ objdump -d test | grep -P "^\d.* <.*plt>"
0000000000001030 <puts@plt>:
0000000000001040 <printf@plt>:
0000000000001050 <__cxa_finalize@plt>:
```

Observamos que en nuestro binario se guardaron referencias de las funciones
que provienen de librerías dinámicas. En este caso, la función puts y la
función printf provienen de libc.

Veamos el ensamblador de la función main para ver cómo llama a
estas funciones.

```
$ objdump -d test
...

0000000000001149 <main>:
    1149:       55                      push   %rbp
    114a:       48 89 e5                mov    %rsp,%rbp
    114d:       48 8d 05 b4 0e 00 00    lea    0xeb4(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    1154:       48 89 c7                mov    %rax,%rdi
    1157:       e8 d4 fe ff ff          call   1030 <puts@plt>
    115c:       be 02 00 00 00          mov    $0x2,%esi
    1161:       48 8d 05 cd 0e 00 00    lea    0xecd(%rip),%rax        # 2035 <_IO_stdin_used+0x35>
    1168:       48 89 c7                mov    %rax,%rdi
    116b:       b8 00 00 00 00          mov    $0x0,%eax
    1170:       e8 cb fe ff ff          call   1040 <printf@plt>
    1175:       b8 00 00 00 00          mov    $0x0,%eax
    117a:       5d                      pop    %rbp
    117b:       c3                      ret

...
```

Notmaos que las funciones que provienen de las librerías externas tienen el
sufijo "@plt", mientras que la función main que declaramos en nuestro código,
no tiene este sufijo.

Estas funciones con el sufijo "@plt" son parte de la procedure linkage table,
pero estas funciones no llaman directamente a la función real de libc, sino
que utilizan la global offset table para obtener la dirección real de la
función.

Probemos a ver el ensamblador de estas funciones:

```
$ objdump -d test
...

0000000000001030 <puts@plt>:
    1030:       ff 25 ca 2f 00 00       jmp    *0x2fca(%rip)        # 4000 <puts@GLIBC_2.2.5>
    1036:       68 00 00 00 00          push   $0x0
    103b:       e9 e0 ff ff ff          jmp    1020 <_init+0x20>

0000000000001040 <printf@plt>:
    1040:       ff 25 c2 2f 00 00       jmp    *0x2fc2(%rip)        # 4008 <printf@GLIBC_2.2.5>
    1046:       68 01 00 00 00          push   $0x1
    104b:       e9 d0 ff ff ff          jmp    1020 <_init+0x20>

...
```

Observamos que estas funciones hacen un jump a una dirección, esa dirección
es de la global offset table.
