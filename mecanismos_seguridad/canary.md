---
layout: default
title: Canary
parent: Mecanismos de Seguridad
nav_order: 2
---

# Canary
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Este mecanismo de seguridad está enfocado en mitigar el error
[Buffer Overflow](../../tipos_errores/espacial/buffer_overflow.html){: .label .label-green }.
Esta protección consiste en  agregar un valor aleatorio arriba de ebp,
este valor es conocido como "canary". Al terminar la ejecución de la función,
se verifica la integridad del canary para determinar si ocurrió un buffer
overflow, y en caso de detectar un cambio en el valor del canary, el
programa termina la ejecución.

---

## Ilustración

Un stack frame con canary se vería de la siguiente forma:

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-0x8                | variables      | ?           |             |
| ebp-0x4                | canary         | ?           |             |
| ebp                    | ebp guardado   | ?           | <- ebp      |
| ebp+0x4                | return address | ?           |             |

Pongamos algunos valores para simular un escenario real.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-0xc                | buffer         | 0x00000000  |             |
| ebp-0x8                | buffer         | 0x00000000  |             |
| ebp-0x4                | canary         | 0x57e8f26a  |             |
| ebp                    | ebp guardado   | 0xffffd2ac  | <- ebp      |
| ebp+0x4                | return address | 0x08049156  |             |

Podemos observar que el canary tiene el valor `0x57e8f26a`. Recordemos que
este valor es aleatorio, por lo que cada vez que se ejecute el binario
tendrá un valor diferente.

Imaginemos que encontramos un buffer overflow en nuestra variable `buffer`.
Intentemos utilizar el buffer overflow para cambiar el return address y
hacer que se ejecuten instrucciones de nuestra elección.

| Direcciones relativas  | Nombres        | Stack       | Registros   |
|:-----------------------|:---------------|:------------|:------------|
| ebp-0xc                | buffer         | 0x41414141  |             |
| ebp-0x8                | buffer         | 0x41414141  |             |
| ebp-0x4                | canary         | 0x41414141  |             |
| ebp                    | ebp guardado   | 0x41414141  | <- ebp      |
| ebp+0x4                | return address | 0xdeadbeef  |             |

Observamos que como el canary siempre estará debajo de nuestras variables
locales en el stack frame, al hacer el buffer overflow cambiamos el valor
del canary, por lo que ahora el canary tiene el valor de `0x41414141`.

Antes de terminar su ejecución, la función verificará la integridad del
canary. En este caso, el programa detectará que el canary ya no tiene el
valor `0x57e8f26a`, lo que significa que ocurrió un buffer overflow y el
programa terminará su ejecución.

---

## Mitiga

Este mecanismo mitiga los siguientes tipos de errores y tipos de explotación:

[Buffer Overflow](../../tipos_errores/espacial/buffer_overflow.html){: .btn .btn-green }
(Parcialmente, ya que solo impide sobreescribir el return address, pero todas
las variables antes del canary pueden ser sobreescritas)

Por lo que probablemente sea mejor intentar otras técnicas contra binarios
que tengan esta protección activada.