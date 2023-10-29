---
layout: default
title: Pwntools
parent: Herramientas
nav_order: 1
---

# Pwntools
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Enlace

[https://docs.pwntools.com/en/stable/](https://docs.pwntools.com/en/stable/)

## Información General

Pwntools es una librería para desarrollo de exploits escrita en python.

## Uso básico

Pwntools es una herramienta muy útil para escribir exploits de explotación
de binarios.

Veamos el siguiente programa:

```c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int obtenerNumeroAleatorio() {
  srand(time(NULL));
  return rand();
}

int leerInputInt() {
  int num;

  scanf("%d", &num);
  getchar();

  return num;
}

int main() {
  int num, guess;

  for (int i = 0; i < 100; i++) {
    num = obtenerNumeroAleatorio();

    printf("Ingresa el siguiente numero: %d\n", num);

    guess = leerInputInt();

    if (guess != num) {
      puts("Numero incorrecto.");
      exit(1);
    }
  }

  puts("Lo lograste!");
}
```

El programa generará 100 números aleatorios y debemos ingresar estos números
para llegar a nuestro objetivo.

Veamos la salida del programa:

```
$ ./output
Ingresa el siguiente numero: 1447230790
1447230790
Ingresa el siguiente numero: 392144257
392144257
Ingresa el siguiente numero: 406755245
40
Numero incorrecto.
```

Hacer este proceso a mano sería muy tardado. Con pwntools podemos interactuar
con el input y output de nuestro binario. Veamos cómo utilizar pwntools para
ejecutar nuestro binario e interactuar con él:

```python
from pwn import * # Importamos pwntools

p = process("./output") # Ejecuta el binario con nombre "output"
```

Probemos a ejecutar nuestro script:

```
$ python3 solve_output.py
[+] Starting local process './output': pid 9602
[*] Stopped process './output' (pid 9602)
```

Observamos que se inició un proceso y se detuvo inmediatamente. Esto ocurrió
debido a que iniciamos nuestro binario, pero se terminó el script y se cerró
el proceso. Para poder interactuar manualmente con nuestro binario, debemos
utilizar el método "interactive".

Script actualizado:

```python
from pwn import * # Importamos pwntools

p = process("./output") # Ejecuta el binario con nombre "output"

p.interactive() # Interactuamos con nuestro binario mediante la terminal
```

Salida:

```
$ python3 solve_output.py
[+] Starting local process './output': pid 13501
[*] Switching to interactive mode
Ingresa el siguiente numero: 1281665990
$ 10
Numero incorrecto.
```

Observamos que esta vez logramos interactuar correctamente con el binario.
Ahora intentemos leer el número aleatorio desde python. Con el método
"recvuntil" podemos leer el output del binario desde la posición actual hasta
encontrar un string específico. El método "recvline" lee desde la posición
actual hasta el final de la línea actual.

Veamos esto en acción:

```python
from pwn import * # Importamos pwntools

p = process("./output") # Ejecuta el binario con nombre "output"

# El programa imprime:  "Ingresa el siguiente numero: x"
# Con recvuntil leemos: "Ingresa el siguiente numero: "
# Ahora estamos posicionados después del string que ya leímos
p.recvuntil(b"Ingresa el siguiente numero: ")


# "Ingresa el siguiente numero: x"
#                               ^ Estamos posicionados aqui
# Utilizar recvline() nos regresará el valor de x
numero = p.recvline()
print("Numero leido desde python:", numero)

p.interactive() # Interactuamos con nuestro binario mediante la terminal
```

Salida:

```
$ python3 solve_output.py
[+] Starting local process './output': pid 2851
Numero leido desde python: b'2067057604\n'
[*] Switching to interactive mode
$
```

Observamos que logramos leer el número desde python. Ahora solo falta
enviarle el número como input a nuestro proceso. Para esto, podemos
utilizar el método "sendline".

```python
from pwn import * # Importamos pwntools

p = process("./output") # Ejecuta el binario con nombre "output"

# El programa imprime:  "Ingresa el siguiente numero: x"
# Con recvuntil leemos: "Ingresa el siguiente numero: "
# Ahora estamos posicionados después del string que ya leímos
p.recvuntil(b"Ingresa el siguiente numero: ")


# "Ingresa el siguiente numero: x"
#                               ^ Estamos posicionados aqui
# Utilizar recvline() nos regresará el valor de x
numero = p.recvline()
numero = numero.strip() # Quitamos el salto de linea
print("Numero leido desde python:", numero)

p.sendline(numero) # Enviamos el numero como input al programa

p.interactive() # Interactuamos con nuestro binario mediante la terminal
```

Salida:

```
$ python3 solve_output.py
[+] Starting local process './output': pid 6936
Numero leido desde python: b'280120686'
[*] Switching to interactive mode
Ingresa el siguiente numero: 280120686
$
```

Observamos que el número se envió correctamente y ahora el programa nos pide
el siguiente número. Para repetir el proceso las 100 veces, podemos utilizar
un ciclo:

```python
from pwn import * # Importamos pwntools

p = process("./output") # Ejecuta el binario con nombre "output"

for _ in range(100):
    # El programa imprime:  "Ingresa el siguiente numero: x"
    # Con recvuntil leemos: "Ingresa el siguiente numero: "
    # Ahora estamos posicionados después del string que ya leímos
    p.recvuntil(b"Ingresa el siguiente numero: ")


    # "Ingresa el siguiente numero: x"
    #                               ^ Estamos posicionados aqui
    # Utilizar recvline() nos regresará el valor de x
    numero = p.recvline()
    numero = numero.strip() # Quitamos el salto de linea
    print("Numero leido desde python:", numero)

    p.sendline(numero) # Enviamos el numero como input al programa

p.interactive() # Interactuamos con nuestro binario mediante la terminal
```

Salida:

```
[x] Starting local process './output'
[+] Starting local process './output': pid 16619
Numero leido desde python: b'1418054671'
Numero leido desde python: b'1109564138'
Numero leido desde python: b'1884436538'
Numero leido desde python: b'1573497005'
Numero leido desde python: b'207638442'
Numero leido desde python: b'2047105026'
Numero leido desde python: b'665781958'
Numero leido desde python: b'1436186415'
Numero leido desde python: b'1125940710'
Numero leido desde python: b'1891238862'
Numero leido desde python: b'1590280724'
Numero leido desde python: b'219389884'
Numero leido desde python: b'989749375'
Numero leido desde python: b'1751234715'
Numero leido desde python: b'374027317'
Numero leido desde python: b'1148827670'
Numero leido desde python: b'837948219'
Numero leido desde python: b'1623906359'
Numero leido desde python: b'227282360'
Numero leido desde python: b'1006932884'
Numero leido desde python: b'708321781'
Numero leido desde python: b'1476003401'
Numero leido desde python: b'102094933'
Numero leido desde python: b'1937043838'
Numero leido desde python: b'569800503'
Numero leido desde python: b'258788225'
Numero leido desde python: b'1024324668'
Numero leido desde python: b'722163187'
Numero leido desde python: b'1494849080'
Numero leido desde python: b'1191005572'
Numero leido desde python: b'1959978871'
Numero leido desde python: b'572735175'
Numero leido desde python: b'1344246572'
Numero leido desde python: b'1047034100'
Numero leido desde python: b'1814553172'
Numero leido desde python: b'433078500'
Numero leido desde python: b'1205681768'
Numero leido desde python: b'1967404356'
Numero leido desde python: b'1664395424'
Numero leido desde python: b'1364022221'
Numero leido desde python: b'2128993582'
Numero leido desde python: b'755716621'
Numero leido desde python: b'1532496908'
Numero leido desde python: b'1224984473'
Numero leido desde python: b'1994573727'
Numero leido desde python: b'616443106'
Numero leido desde python: b'306448530'
Numero leido desde python: b'11759973'
Numero leido desde python: b'779481774'
Numero leido desde python: b'477958586'
Numero leido desde python: b'164139070'
Numero leido desde python: b'944388307'
Numero leido desde python: b'1709738685'
Numero leido desde python: b'1407331173'
Numero leido desde python: b'1098058656'
Numero leido desde python: b'1864504510'
Numero leido desde python: b'1560125284'
Numero leido desde python: b'190888884'
Numero leido desde python: b'2024224764'
Numero leido desde python: b'1727801221'
Numero leido desde python: b'344234596'
Numero leido desde python: b'45610127'
Numero leido desde python: b'814249246'
Numero leido desde python: b'507382769'
Numero leido desde python: b'1279901387'
Numero leido desde python: b'2062350429'
Numero leido desde python: b'678689554'
Numero leido desde python: b'1434098708'
Numero leido desde python: b'58699817'
Numero leido desde python: b'823819839'
Numero leido desde python: b'1608822667'
Numero leido desde python: b'1290523973'
Numero leido desde python: b'994476396'
Numero leido desde python: b'1758434902'
Numero leido desde python: b'1469382822'
Numero leido desde python: b'77728461'
Numero leido desde python: b'850308332'
Numero leido desde python: b'1627157265'
Numero leido desde python: b'243290519'
Numero leido desde python: b'2086446425'
Numero leido desde python: b'711540453'
Numero leido desde python: b'407927890'
Numero leido desde python: b'1171145619'
Numero leido desde python: b'871817955'
Numero leido desde python: b'1635658809'
Numero leido desde python: b'1336713970'
Numero leido desde python: b'2105778765'
Numero leido desde python: b'722473741'
Numero leido desde python: b'425502169'
Numero leido desde python: b'124420998'
Numero leido desde python: b'1962753646'
Numero leido desde python: b'1645221493'
Numero leido desde python: b'1349557837'
Numero leido desde python: b'2117595089'
Numero leido desde python: b'744259269'
Numero leido desde python: b'1511146202'
Numero leido desde python: b'136460094'
Numero leido desde python: b'1977459508'
Numero leido desde python: b'1683005876'
Numero leido desde python: b'291546188'
[*] Switching to interactive mode
[*] Process './output' stopped with exit code 0 (pid 16619)
Lo lograste!
```

Vemos que con la ayuda de pwntools logramos automatizar todo el proceso.

Esta fue una demostración básica del uso de pwntools, ya que pwntools
cuenta con una gran cantidad de utilidades que podemos utilizar.
