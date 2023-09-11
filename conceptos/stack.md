---
layout: default
title: Stack
parent: Conceptos
nav_order: 1
---

# Stack

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

#### Paso 1

```c
int main() {
  int var1 = 0; // <- eip
  int var2 = 1;
  int var3 = 2;
}
```

#### Paso 2

```c
int main() {
  int var1 = 0;
  int var2 = 1; // <- eip
  int var3 = 2;
}
```

#### Paso 3

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

Una vez que se reservó el espacio, las siguientes instrucciones de ensamblador
se encargan de guardar en el stack el valor de nuestras variables

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

| Dirección    | Nombres      | Stack       | Registros   |
|:-------------|:-------------|:------------|:------------|
| 984          | ?            | ?           | <- esp      |
| 988          | var1         | 0x00000000  |             |
| 992          | var2         | 0x00000001  |             |
| 996          | var3         | 0x00000002  |             |
| 1000         | ?            | ?           | <- ebp      |

esp = 984
{: .label }

---

### ebp

El registro ebp (Base Pointer) apunta a la base del stack.

Para entender este registro, necesitaremos un ejemplo más complejo:

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5;
  stack();
  int var2 = 10;
}
```

Repasemos el ejemplo del registro eip:

#### Paso 1

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5; // eip
  stack();
  int var2 = 10;
}
```

#### Paso 2

```c
void foo() {
  int var1 = 5;
}

int main() {
  int var1 = 5;
  stack(); // eip
  int var2 = 10;
}
```

#### Paso 3

```c
void foo() {
  int var1 = 5; // eip
}

int main() {
  int var1 = 5;
  stack();
  int var2 = 10;
}
```

En este paso sucede algo interesante. Debido a que se hizo una llamada a la
función foo, el registro eip ahora apunta a la función foo.

La segunda cosa interesante que sucede es que se llegó al final de
la función foo, por lo que eip debe regresar a la función main, pero
¿cómo es que sucede esto?. Es evidente que la función foo no llama
a la función main, entonces, ¿cómo es que regresa a la función main?.

