---
layout: default
title: Use After Free
grand_parent: Tipos de errores
parent: Errores relacionados con la seguridad temporal
nav_order: 1
---

# Use After Free
{: .no_toc }

## Conocimientos necesarios
{: .no_toc .text-delta }

Antes de comenzar con esta sección, es recomendable que leas las siguientes
secciones de la guía si aún no las has leído:

[Heap](../../conceptos/heap.html){: .btn .btn-green }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Cuando se utiliza memoria del heap, el programador es responsable de
liberar esa memoria cuando ya no será utilizada. Use after free es un
bug que ocurre cuando el programa utiliza memoria que ya ha sido liberada
previamente.

---

## Ejemplo

Veamos el siguiente código en lenguaje C:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PENDIENTES_MAX  8

typedef struct usuario {
  int admin;
  char nombre[124];
} usuario;

typedef struct pendiente {
  unsigned int size;
  char* contenido;
} pendiente;

usuario* usuarioActivo = NULL;
pendiente pendientes[PENDIENTES_MAX];

int leerInt() {
  int opcion;
  scanf("%d", &opcion);
  getchar();

  return opcion;
}

int menu() {
  int opcion;

  puts("Elige una accion a realizar");
  puts("1. Agregar pendiente");
  puts("2. Editar pendiente");
  puts("3. Borrar pendiente");
  puts("4. Mostrar pendiente");
  puts("5. Iniciar sesion");
  puts("6. Salir");
  puts(">>");

  return leerInt();
}

void agregar_pendiente() {
  unsigned int textSize;

  puts("Ingresa el tamanio del pendiente");
  textSize = leerInt();

  for (int i = 0; i < PENDIENTES_MAX; i++) {
    if (!pendientes[i].contenido) {
      pendientes[i].contenido = (char*)malloc(textSize * sizeof(char));
      pendientes[i].size = textSize;
      break;
    }
  }
}

void editar_pendiente() {
  unsigned int idx;

  puts("Ingresa el indice del pendiente a editar");
  idx = leerInt();

  if (idx >= 0 && idx < PENDIENTES_MAX && pendientes[idx].contenido) {
    puts("Ingrese el contenido del pendiente");
    fgets(pendientes[idx].contenido, pendientes[idx].size, stdin);
  } else {
    puts("Indice invalido");
  }
}

void borrar_pendiente() {
  unsigned int idx;

  puts("Ingresa el indice del pendiente a borrar");
  idx = leerInt();

  if (idx >= 0 && idx < PENDIENTES_MAX && pendientes[idx].contenido) {
    free(pendientes[idx].contenido);
  } else {
    puts("Indice invalido");
  }
}

void mostrar_pendiente() {
  unsigned int idx;

  puts("Ingresa el indice del pendiente a mostrar");
  idx = leerInt();

  if (idx >= 0 && idx < PENDIENTES_MAX && pendientes[idx].contenido) {
    puts(pendientes[idx].contenido);
  } else {
    puts("Indice invalido");
  }
}

void iniciar_sesion() {
  if (!usuarioActivo) {
    usuarioActivo = (usuario*)malloc(sizeof(usuario));
    memset(usuarioActivo, 0, sizeof(usuario));
  }

  puts("Ingresa el nombre de tu usuario");
  fgets(usuarioActivo->nombre, 124, stdin);

  if (usuarioActivo->admin) {
    puts("Esta cuenta tiene permisos de administrador");
  } else {
    puts("Esta cuenta es un usuario normal");
  }
}

int main() {
  int opcion;

  while ((opcion = menu()) != 6) {
    switch (opcion) {
      case 1:
        agregar_pendiente();
        break; 
      case 2:
        editar_pendiente();
        break; 
      case 3:
        borrar_pendiente();
        break; 
      case 4:
        mostrar_pendiente();
        break; 
      case 5:
        iniciar_sesion();
        break; 
      default:
        puts("Opcion invalida"); 
    }
  }
}
```

El código es bastante extenso, pero servirá para probar lo crítico que
puede llegar a ser un use after free.

Veamos dónde está el bug en el código:

```c
void borrar_pendiente() {
  unsigned int idx;

  puts("Ingresa el indice del pendiente a borrar");
  idx = leerInt();

  if (idx >= 0 && idx < PENDIENTES_MAX && pendientes[idx].contenido) {
    free(pendientes[idx].contenido);
  } else {
    puts("Indice invalido");
  }
}
```

El problema que podemos identificar, es que al borrar un pendiente, llamamos
a la función free correctamente, pero dejamos el pointer al heap en el
arreglo. La forma de corregir este problema sería eliminar el pointer
del arreglo después de llamar a free.

```c
void borrar_pendiente() {
  unsigned int idx;

  puts("Ingresa el indice del pendiente a borrar");
  idx = leerInt();

  if (idx >= 0 && idx < PENDIENTES_MAX && pendientes[idx].contenido) {
    free(pendientes[idx].contenido);
    pendientes[idx].contenido = NULL;
  } else {
    puts("Indice invalido");
  }
}
```

Pero debido a que no se elimina el pointer, podemos seguir editando
el chunk incluso aunque ya fue liberado.

Veamos cómo podemos aprovechar esto para convertirnos en administradores
en el programa.

```c
void iniciar_sesion() {
  if (!usuarioActivo) {
    usuarioActivo = (usuario*)malloc(sizeof(usuario));
    memset(usuarioActivo, 0, sizeof(usuario));
  }

  puts("Ingresa el nombre de tu usuario");
  fgets(usuarioActivo->nombre, 124, stdin);

  if (usuarioActivo->admin) {
    puts("Esta cuenta tiene permisos de administrador");
  } else {
    puts("Esta cuenta es un usuario normal");
  }
}
```

Vemos que los datos del usuario son guardados en el heap, ya que el
programa llama a malloc para reservar la memoria necesaria para guardar
los datos del usuario.

Vemos que la cantidad de bytes que reserva es `sizeof(usuario)`.

```c
typedef struct usuario {
  int admin;
  char nombre[124];
} usuario;
```

El struct usuario tiene 2 campos, uno de tipo int (4 bytes) y un
arreglo de 124 caracteres (124 bytes), por lo que reserva un total de
128 bytes.

Ahora, recordemos, ¿qué pasaría si reservamos 128 bytes para un pendiente y
después liberamos esa memoria?. La respuesta es que la próxima vez que
llamemos a malloc para pedir 128 bytes, nos regresará la dirección que
liberamos.

Pongámoslo a prueba:

Salida

```
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
1
Ingresa el tamanio del pendiente
128
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
3
Ingresa el indice del pendiente a borrar
0
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
1
Ingresa el tamanio del pendiente
128
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
2
Ingresa el indice del pendiente a editar
0
Ingrese el contenido del pendiente
Este debe ser el pendiente 0
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
4
Ingresa el indice del pendiente a mostrar
0
Este debe ser el pendiente 0

Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
4
Ingresa el indice del pendiente a mostrar
1
Este debe ser el pendiente 0
```

Podemos ver que debido a que liberamos el pendiente 0, al pendiente 1 se le
asigna el chunk que tenía el pendiente 0, pero debido al use after free, si
modificamos el pendiente 0 vemos que también cambia el pendiente 1, ya que
ambos apuntan a la misma dirección de memoria.

Ahora hagamos lo mismo, pero esta vez haremos que nuestro pendiente 0
y nuestro usuarioActual apunten a la misma dirección.

```
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
1
Ingresa el tamanio del pendiente
128
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
3
Ingresa el indice del pendiente a borrar
0
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
5
Ingresa el nombre de tu usuario
admin
Esta cuenta es un usuario normal
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
2
Ingresa el indice del pendiente a editar
0
Ingrese el contenido del pendiente
AAAAAAAAAA
Elige una accion a realizar
1. Agregar pendiente
2. Editar pendiente
3. Borrar pendiente
4. Mostrar pendiente
5. Iniciar sesion
6. Salir
>>
5
Ingresa el nombre de tu usuario
admin
Esta cuenta tiene permisos de administrador
```

Debido a que el usuarioActual y el pendiente 0 apuntaban a la misma
dirección, cuando modificamos el pendiente 0, modificamos el valor de
admin del usuario, por lo que al iniciar sesión por segunda vez, el
programa nos imprime el mensaje de que estamos en una cuenta con
permisos de administrador.

## Retos

---

### uaf1

¿Podrás utilizar el use after free para obtener la password del usuario root?.

Archivos:

[uaf1](../../retos/uaf/uaf1.zip){: .btn .btn-blue }
