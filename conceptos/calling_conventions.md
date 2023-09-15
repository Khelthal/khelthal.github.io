---
layout: default
title: Calling Conventions
parent: Conceptos
nav_order: 2
---

# Calling Conventions
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Se conoce como calling conventions a la forma que se utiliza para pasarle
argumentos a una función.

Tomemos como ejemplo el siguiente código:

```c
int foo(int a, int b) {
  return a + b;
}

int main() {
  foo(5, 8);
}
```

En este código, la función main llama a la función foo y le pasa los argumentos
5 y 8.

Los calling conventions establecen el procedimiento que se utilizará para
pasar los valores 5 y 8 a la función foo.

Los calling conventions dependen de varios factores, como la arquitectura con
la que se compiló el código y el sistema operativo.

---

## Ejemplos

Retomemos nuestro código en lenguaje C:

```c
int foo(int a, int b) {
  return a + b;
}

int main() {
  foo(5, 8);
}
```

Veamos el ensamblador producido al compilar el código en arquitectura de
32-bit en linux.

```nasm
main:
  push   ebp
  mov    ebp,esp
  push   0x8
  push   0x5
  call   foo
  add    esp,0x8
  mov    eax,0x0
  leave
  ret
```

Prestemos atención a las dos instrucciones anteriores a la llamada de la
función foo.

```nasm
; main:
;   push   ebp
;   mov    ebp,esp
  push   0x8
  push   0x5
;   call   foo
;   add    esp,0x8
;   mov    eax,0x0
;   leave
;   ret
```

Antes de la instrucción `call foo`, el programa está empujando al stack los
valores 8 y 5. Si observamos, estos son los parámetros que le está pasando
a la función foo. En 32-bit, los parámetros son pasados a una función a través
del stack.

Veamos otra vez el ensamblador de la función main, pero esta vez el
binario fue compilado en arquitectura de 64-bit.

```nasm
main:
  push   rbp
  mov    rbp,rsp
  mov    esi,0x8
  mov    edi,0x5
  call   foo
  mov    eax,0x0
  pop    rbp
  ret
```

Observamos que en este caso, los argumentos los pasa a la función foo
a través de los registros.
