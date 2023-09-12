---
layout: default
title: Stack
parent: Conceptos
nav_order: 1
---

# Stack
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

El stack es una región de memoria utilizada principalmente para almacenar
el valor de las variables locales de una función.

Tomemos como ejemplo el siguiente código en lenguaje C:

```c
int main() {
  int var1 = 0;
  int var2 = 1;
  int var3 = 2;
}
```

El stack para almacenar el contenido de las variables declaradas
en el código anterior sería algo similar a la siguiente tabla:

| Nombres      | Stack       |
|:-------------|:------------|
| var1         | 0x00000000  |
| var2         | 0x00000001  |
| var3         | 0x00000002  |

En el ejemplo anterior solo se ilustraron las variables almacenadas, pero
el stack almacena otros datos importantes.

---

## Registros eip, esp y ebp

Es conveniente conocer los registros eip, esp y ebp para entender mejor
el funcionamiento del stack, ya que estos registros contienen datos
necesarios para el funcionamiento del mismo.

---

### eip

El registro eip (Instruction Pointer) es utilizado para almacenar la
dirección de la instrucción que se está ejecutando actualmente.

Por ejemplo, consideremos el código en lenguaje C:

```c
int main() {
  int var1 = 0;
  int var2 = 1;
  int var3 = 2;
}
```

Si pensamos en la instrucción eip a nivel código fuente, la ejecución del
programa se vería en 3 pasos.

Paso 1
{: .label .label-purple }

```c
int main() {
  int var1 = 0; // <- eip
  int var2 = 1;
  int var3 = 2;
}
```

Paso 2
{: .label .label-purple }

```c
int main() {
  int var1 = 0;
  int var2 = 1; // <- eip
  int var3 = 2;
}
```

Paso 3
{: .label .label-purple }

```c
int main() {
  int var1 = 0;
  int var2 = 1;
  int var3 = 2; // <- eip
}
```

Se observa que eip recorrió en orden las instrucciones dentro de la
función main.

Lo anterior fue un ejemplo simplificado. Lo que realmente ocurre es que el
código en lenguaje C es compilado. Al ser compilado, la función main
es convertida a un código ensamblador parecido al siguiente:

```nasm
push   ebp
mov    ebp,esp
sub    esp,0x10
mov    DWORD PTR [ebp-0xc],0x0
mov    DWORD PTR [ebp-0x8],0x1
mov    DWORD PTR [ebp-0x4],0x2
mov    eax,0x0
leave
ret
```
Y son estas instrucciones las que el registro eip recorre en orden.

---

### esp

El registro esp (Stack Pointer) apunta a la cima del stack.

Consideremos el mismo código en lenguaje C:

```c
int main() {
  int var1 = 0;
  int var2 = 1;
  int var3 = 2;
}
```

Antes vimos una aproximación de cómo se verían las 3 variables declaradas
en la función main en el stack.

Para almacenar estas variables en el stack, se reserva el espacio necesario.

Prestemos atención a la versión ensamblador de la función main:

```nasm
; push   ebp
; mov    ebp,esp
sub    esp,0x10
mov    DWORD PTR [ebp-0xc],0x0
mov    DWORD PTR [ebp-0x8],0x1
mov    DWORD PTR [ebp-0x4],0x2
; mov    eax,0x0
; leave
; ret
```

Solo nos enfocaremos en las instrucciones que no están comentadas.

Supongamos que inicialmente el stack está vacío:

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 1000         | ?            | ?           | <- ebp, esp |

esp = 1000
{: .label }

Algo particular sobre el stack, es que crece hacía direcciones más bajas. Esto
significa que al hacer crecer el stack, el valor de esp se debe hacer más
pequeño. Debido a esto, vemos la instrucción:

```nasm
; push   ebp
; mov    ebp,esp
sub    esp,0x10
; mov    DWORD PTR [ebp-0xc],0x0
; mov    DWORD PTR [ebp-0x8],0x1
; mov    DWORD PTR [ebp-0x4],0x2
; mov    eax,0x0
; leave
; ret
```

La instrucción sub (substract) se encarga de restar. En este caso le está
restando 16 al registro esp.

Esta instrucción está haciendo crecer el tamaño del stack para que tenga
espacio suficiente para guardar el valor de nuestras variables.

Como nuestras variables son de tipo int, cada una requiere 4 bytes para
almacenarse, y por lo tanto, se requieren 12 bytes para almacenar el
valor de las 3. En este caso, el compilador reservó 0x10 bytes (16 en decimal)
para poder guardar los valores de nuestras variables.

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | var1         | ?           |             |
| 992          | var2         | ?           |             |
| 996          | var3         | ?           |             |
| 1000         | ?            | ?           | <- ebp      |

esp = 984
{: .label }

Una vez reservado el espacio, lo siguiente es almacenar los valores
de las variables en el stack. Para eso, es necesario el uso del
registro ebp.

---

### ebp

El registro ebp (Base Pointer) apunta a la base del stack.

Retomando el ejemplo anterior, después de haber reservado el espacio en
el stack necesario para almacenar el valor de nuestras variables, el siguiente
paso es guardar el valor de nuestras variables en el stack. Las siguientes
instrucciones de ensamblador se encargan de guardar en el stack el valor de
nuestras variables.

```nasm
; push   ebp
; mov    ebp,esp
; sub    esp,0x10
mov    DWORD PTR [ebp-0xc],0x0
mov    DWORD PTR [ebp-0x8],0x1
mov    DWORD PTR [ebp-0x4],0x2
; mov    eax,0x0
; leave
; ret
```

Si observamos, podemos notar que las 3 instrucciones utilizan el registro
ebp. Este registro es usado como una "base" o pivote para acceder
a las variables locales de la función.

Prestemos atención al stack antes de almacenar el valor de las variables.

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | var1         | ?           |             |
| 992          | var2         | ?           |             |
| 996          | var3         | ?           |             |
| 1000         | ?            | ?           | <- ebp      |

esp = 984
{: .label }

ebp = 1000
{: .label }

La primera instrucción almacena el valor 0x0 en la dirección ebp-0xc (1000-12),
por lo que el stack resultante sería:

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | var1         | 0x00000000  |             |
| 992          | var2         | ?           |             |
| 996          | var3         | ?           |             |
| 1000         | ?            | ?           | <- ebp      |

esp = 984
{: .label }

ebp = 1000
{: .label }

Las siguientes 2 instrucciones almacenan el valor 0x1 en ebp-0x8 y
0x2 en ebp-0x4.

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | var1         | 0x00000000  |             |
| 992          | var2         | 0x00000001  |             |
| 996          | var3         | 0x00000002  |             |
| 1000         | ?            | ?           | <- ebp      |

esp = 984
{: .label }

ebp = 1000
{: .label }

Debido a que el registro ebp se utiliza para acceder a las variables locales
de una función, cada función debe tener su propio valor de ebp, por lo
que es necesario guardar los valores de ebp anteriores en el stack.

---

## Simulación de ejecución

Veamos cómo funciona el stack en un ejemplo un poco más complejo:

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5;
  foo();
  int var2 = 10;
}
```

Repasemos el ejemplo del registro eip:

Paso 1
{: .label .label-purple }

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5; // eip
  foo();
  int var2 = 10;
}
```

Paso 2
{: .label .label-purple }

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5;
  foo(); // eip
  int var2 = 10;
}
```

Paso 3
{: .label .label-purple }

```c
void foo() {
  int var1 = 5; // eip
}

int main() {
  int var1 = 5;
  foo();
  int var2 = 10;
}
```

En este paso sucede algo interesante. Debido a que se hizo una llamada a la
función foo, el registro eip ahora apunta a la función foo.

La segunda cosa interesante que sucede es que se llegó al final de
la función foo, por lo que eip debe regresar a la función main, pero
¿cómo es que sucede esto?. Es evidente que la función foo no llama
a la función main, entonces, ¿cómo es que regresa a la función main?.

Para entender el funcionamiento completo del stack es conveniente ver el
ensamblador de la función main y la función foo.

```nasm
foo:
  push   ebp                        ; foo + 0
  mov    ebp,esp                    ; foo + 1
  sub    esp,0x10                   ; foo + 3
  mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
  leave                             ; foo + 13
  ret                               ; foo + 14

main:
  push   ebp                        ; main + 0
  mov    ebp,esp                    ; main + 1
  sub    esp,0x10                   ; main + 3
  mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
  call   foo                        ; main + 13
  mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
  mov    eax,0x0                    ; main + 25
  leave                             ; main + 30
  ret                               ; main + 31
```

main = 500
{: .label }


foo = 485
{: .label }


Para propósitos de este ejemplo asumiremos que la dirección donde empieza
la función main es 500 y la dirección donde empieza la función foo es 485.
También asumiremos que el valor de ebp para main es 1000.

Empezaremos a simular la ejecución a partir de main + 3.

Paso 1
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
  sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 503
{: .label }

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 1000         | ?            | ?           | <- ebp, esp |

ebp = 1000
{: .label }

esp = 1000
{: .label }

Esta instrucción hará crecer el stack para tener espacio suficiente para
almacenar el valor de nuestras variables.


Paso 2
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
  mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 506
{: .label }


| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | ?            | ?           |             |
| 992          | var1         | ?           |             |
| 996          | var2         | ?           |             |
| 1000         | ?            | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 984
{: .label }

Esta instrucción guardará el valor de la variable var1 en el stack.

Paso 3
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
  call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 513
{: .label }


| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | ?            | ?           |             |
| 992          | var1         | 0x00000005  |             |
| 996          | var2         | ?           |             |
| 1000         | ?            | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 984
{: .label }

En esta instrucción es donde responderemos la pregunta que se planteó
anteriormente. Después de llamar a la función foo, el nuevo valor
de eip será 485 (foo + 0) y al terminal de ejecutar la función foo,
el valor de eip debería ser 518 (main + 18). Pero, ¿cómo puede la función
foo saber que debe regresar a main + 18?, la respuesta está en el stack.
La instrucción call hace 2 cosas. Guarda la dirección de la siguiente
instrucción en el stack y cambia el valor de eip a la dirección de
la función a la que se llamó.

Paso 4
{: .label .label-purple }


```nasm
; foo:
  push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 485
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 980          | return address | 0x00000206  | <- esp      |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 980
{: .label }

Observemos el estado del stack después de haber ejecutado la instrucción call.
Podemos observar que el valor de esp ha cambiado, ya que se ha insertado un
nuevo elemento en el stack. Este elemento es la dirección a la que debe
regresar eip después de terminar de ejecutar la función foo. Comúnmente
se le conoce a esta dirección como "return address", debido a que es
la dirección a la que debe regresar la función al terminar de ejecutarse.
En este caso vemos que el return address es 0x206 (518 en decimal, la dirección
de main + 18).

Lo siguiente en lo que debemos pensar es en ebp. Recordemos que cada función
tiene sus propias variables locales, y que para acceder a sus variables locales
utiliza el registro ebp como pivote. Ahora que nos encontramos en la función
foo, necesitamos cambiar el valor de ebp para acceder a las variables locales
de la función foo. La pregunta que surge entonces es, si cambiamos el valor
de ebp, ¿cómo haremos para acceder a las variables locales de main una vez
que terminemos de ejecutar la función foo?. Una vez más, la respuesta se
encuentra en el stack.

Para evitar perder el valor de ebp de la función main, antes de cambiar
el valor de ebp, lo guardamos en el stack para poder recuperarlo al
finalizar la función foo.

la instrucción actual, push ebp, hace exactamente eso, "empujar" en el
stack el valor actual de ebp.


Paso 5
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
  mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 486
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 976          | ebp guardado   | 0x000003e8  | <- esp      |
| 980          | return address | 0x00000206  |             |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 976
{: .label }

Vemos que después de ejecutar la instrucción anterior, el valor de
ebp ya se encuentra guardado en el stack. Una vez que ya guardamos
el valor de ebp, el siguiente paso es cambiar el valor de ebp
para obtener el ebp que servirá como pivote para las variables locales
de la función foo. La instrucción actual, `mov ebp, esp`, se encarga de
eso. Reemplaza el valor de ebp con el valor acutal de esp.


Paso 6
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
  sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 488
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 976          | ebp guardado   | 0x000003e8  | <- ebp, esp |
| 980          | return address | 0x00000206  |             |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           |             |

ebp = 976
{: .label }

esp = 976
{: .label }

Observamos que ahora el valor de ebp y esp son iguales. El siguiente paso
es incrementar el tamaño del stack para tener espacio para guardar nuestras
variables.


Paso 7
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
  mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 491
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 960          | ?              | ?           | <- esp      |
| 964          | ?              | ?           |             |
| 968          | ?              | ?           |             |
| 972          | var1           | ?           |             |
| 976          | ebp guardado   | 0x000003e8  | <- ebp      |
| 980          | return address | 0x00000206  |             |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           |             |

ebp = 976
{: .label }

esp = 960
{: .label }

La instrucción actual guardará el valor de var1 en el stack.


Paso 8
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
  leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 498
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 960          | ?              | ?           | <- esp      |
| 964          | ?              | ?           |             |
| 968          | ?              | ?           |             |
| 972          | var1           | 0x00000005  |             |
| 976          | ebp guardado   | 0x000003e8  | <- ebp      |
| 980          | return address | 0x00000206  |             |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           |             |

ebp = 976
{: .label }

esp = 960
{: .label }

Si recordamos, la función foo lo único que hace es asignar el valor 5 a la
variable var1. Eso significa que en este punto, ya se terminó de ejecutar
la función foo. Las siguientes instrucciones se encargan de regresar
la ejecución a la función main. La instrucción actual, `leave`, se encarga
de 2 cosas:

1. Liberar el espacio ocupado por las variables locales de la función foo en
el stack.

1. Sacar el valor de ebp guardado del stack y asignarlo al registro ebp para
recuperar el ebp de la función anterior (en este caso main).


Paso 9
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
  ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
;   mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 499
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 980          | return address | 0x00000206  | <- esp      |
| 984          | ?              | ?           |             |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 980
{: .label }

Una vez que decrementamos el tamaño del stack y recuperamos el valor de ebp
de main, lo único que falta es obtener el return address que tenemos guardado
en el stack y asignarlo a eip.

La instrucción `ret` se encarga de este trabajo. Esta instrucción saca
el valor que está en la cima del stack (debido a las operaciones
realizadas por la instrucción `leave`, este valor será el return address) y
asigna ese valor al registro eip.


Paso 10
{: .label .label-purple }


```nasm
; foo:
;   push   ebp                        ; foo + 0
;   mov    ebp,esp                    ; foo + 1
;   sub    esp,0x10                   ; foo + 3
;   mov    DWORD PTR [ebp-0x4],0x5    ; foo + 6
;   leave                             ; foo + 13
;   ret                               ; foo + 14
; 
; main:
;   push   ebp                        ; main + 0
;   mov    ebp,esp                    ; main + 1
;   sub    esp,0x10                   ; main + 3
;   mov    DWORD PTR [ebp-0x8],0x5    ; main + 6
;   call   foo                        ; main + 13
  mov    DWORD PTR [ebp-0x4],0xa    ; main + 18
;   mov    eax,0x0                    ; main + 25
;   leave                             ; main + 30
;   ret                               ; main + 31
```

eip = 518
{: .label }


| Dirección    | Nombres        | Stack       | Registros   |
|:-------------|:---------------|:------------|:------------|
| 984          | ?              | ?           | <- esp      |
| 988          | ?              | ?           |             |
| 992          | var1           | 0x00000005  |             |
| 996          | var2           | ?           |             |
| 1000         | ?              | ?           | <- ebp      |

ebp = 1000
{: .label }

esp = 984
{: .label }

Después de que se ejecutó la instrucción ret, regresamos a la función
main y observamos que el stack tiene la misma estructura que tenía
antes de llamar a la función foo.

El resto de instrucciones es el mismo proceso que vimos en la función foo.
Asignar el valor de var2, usar la instrucción `leave` para recuperar
el espacio utilizado por las variables locales de la función main y para
recuperar el valor de ebp de la función anterior y finalmente la instrucción
`ret` para regresar a la función anterior.

Después de esta simulación de ejecución, podemos notar que las funciónes
que teníamos en lenguaje C, al ser compiladas, el ensamblador resultante
tiene una estructura que es igual en todas las funciones.

Esta estructura se puede ver de la siguiente manera:

```nasm
 push   ebp                        ; Guardar el valor de ebp de la función anterior
 mov    ebp,esp                    ; Actualizar el valor de ebp para obtener el base pointer de la función actual
 sub    esp,NUMERO                 ; Reservar espacio para las variables locales
; Instrucciones a realizar por la función
 leave                             ; Liberar espacio en el stack y recuperar el valor de ebp de la función anterior
 ret                               ; Regresar a la función anterior
```

También podemos observar que cada función tiene un "pedazo" del stack, en el
cual guarda datos que necesita para manipular sus variables locales y para
regresar a la función anterior al finalizar. Estos "pedazos" que cada función
tiene se conocen como "stack frame".

---

## Stack Frame
