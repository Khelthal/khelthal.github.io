---
layout: default
title: Heap
parent: Conceptos
nav_order: 5
---

# Heap
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Como vimos anteriormente, el stack se utiliza para guardar variables de una
función. Sin embargo, existen casos donde el stack no es suficiente. Una
limitación del stack es que el tamaño de las variables que almacena debe
conocerse en tiempo de compilación.

Por ejemplo, supongamos que queremos guardar una lista de videojuegos
que hemos jugado. Esta lista irá creciendo con el tiempo a medida que agreguemos
nuevos elementos, por lo que es imposible saber en tiempo de compilación el
tamaño que tendrá.

Para guardar dicha lista en el stack, forzosamente tendríamos que darle un tamaño
máximo a la lista y a los nombres de los videojuegos, por ejemplo:

```c
int main() {
  char lista_videojuegos[100][20];
}
```

Pero hay varios problemas que se producen en este caso. Los más evidentes son:
¿qué pasa si ya jugué más de 100 videojuegos? o ¿qué pasa si el título del
juego supera los 20 caracteres?. Por supuesto que podríamos aumentar el tamaño
tanto como de la lista como de los caracteres, pero ¿qué pasa si solo he jugado
1 videojuego?, habría mucho espacio desperdiciado.

Para casos donde no podemos saber el tamaño de las variables en tiempo de
compilación, debemos recurrir al heap. El heap nos permite reservar memoria
de forma dinámica conforme la necesitemos. Podemos reescribir nuestra lista
de la siguiente forma:

```c
#include <stdlib.h>
#include <stdio.h>

typedef struct lista {
  unsigned int capacidad;
  unsigned int tamanio;
  char** contenido;
} lista;

void agregar(lista* lista) {
  unsigned int text_size;

  puts("Ingresa el tamanio del titulo del videojuego");
  scanf("%u\n", &text_size);

  if (lista->capacidad == lista->tamanio) {
    lista->capacidad++;
    char** contenido = lista->contenido;
    lista->contenido = (char**)malloc(lista->capacidad * sizeof(char*));

    for (int i = 0; i < lista->tamanio; i++) {
      lista->contenido[i] = contenido[i];
    }

    free(contenido);
  }

  lista->contenido[lista->tamanio] = (char*) malloc(text_size * sizeof(char));
  fgets(lista->contenido[lista->tamanio], text_size, stdin);
  lista->tamanio++;
}

void imprimir(lista* lista) {
  for (int i = 0; i < lista->tamanio; i++) {
    puts(lista->contenido[i]);
  }
}

int main() {
  lista lista_videojuegos;
  lista_videojuegos.capacidad = 1;
  lista_videojuegos.tamanio = 0;
  lista_videojuegos.contenido = (char**)malloc(lista_videojuegos.capacidad * sizeof(char*));
}
```

Lo importante a notar en este ejemplo, es que utilizamos la función malloc
para solicitar memoria de forma dinámica. De esta forma, podemos almacenar
títulos de cualquier tamaño y la lista puede crecer conforme sea necesario.

Es importante mencionar que el programador está a cargo de la memoria que
reserva en el heap, por lo que cuando la memoria reservada en el heap
ya no sea necesaria, el programador debe liberar esta memoria manualmente
con el uso de la función free.

---

## Detalles importantes

El heap tiene un funcionamiento complejo que va más allá del alcance de
esta guía, por lo que veremos de forma simplificada algunos detalles
necesarios para la guía.

---

Detalle 1
{: .label }

Al reservar memoria con malloc, la función crea una estructura de datos
llamada chunk. Un chunk tiene varias propiedades, como tamaño y data.
La propiedad data es el espacio que utilizamos de la memoria que nos
entrega malloc.

Las operaciones realizadas internamente en el heap cambian dependiendo
del tamaño de un chunk, es decir, los chunks pequeños no son procesados
de la misma forma que los chunks grandes.

---

Detalle 2
{: .label }


Reservar memoria en el heap es una operación costosa, por lo que la función
malloc intentará regresar memoria libre que ya ha sido reservada antes.

Caso 1
{: .label .label-purple }

Veamos el siguiente ejemplo:

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  void *p1, *p2;

  p1 = malloc(128);

  printf("La direccion de la memoria reservada por malloc para p1 es: %p\n", p1);

  free(p1); // Liberando memoria de p1

  p2 = malloc(128);
  
  printf("La direccion de la memoria reservada por malloc para p2 es: %p\n", p2);
}
```

Salida

```
La direccion de la memoria reservada por malloc para p1 es: 0x561367bd22a0
La direccion de la memoria reservada por malloc para p2 es: 0x561367bd22a0
```

Observamos que la función malloc le entrega a p2 la misma dirección que le
había entregado a p1. Esto se debe a que como la memoria de p1 fue liberada,
la operación menos costosa para malloc es darle a p2 la misma memoria que
ya había entregado a p1.

Caso 2
{: .label .label-purple }

Si removemos la llamada a free, observamos que malloc entregará dos
direcciones diferentes para p1 y p2.

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  void *p1, *p2;

  p1 = malloc(128);

  printf("La direccion de la memoria reservada por malloc para p1 es: %p\n", p1);

  // free(p1); // Liberando memoria de p1

  p2 = malloc(128);
  
  printf("La direccion de la memoria reservada por malloc para p2 es: %p\n", p2);
}
```

Salida

```
La direccion de la memoria reservada por malloc para p1 es: 0x5637d02db2a0
La direccion de la memoria reservada por malloc para p2 es: 0x5637d02db740
```

Caso 3
{: .label .label-purple }

También, si solicitamos más memoria para p2, la función malloc nos dará
otra dirección, debido a que no puede reciclar la memoria que le había
dado a p1 porque no tiene el tamaño necesario.

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  void *p1, *p2;

  p1 = malloc(128);

  printf("La direccion de la memoria reservada por malloc para p1 es: %p\n", p1);

  free(p1); // Liberando memoria de p1

  p2 = malloc(256);
  
  printf("La direccion de la memoria reservada por malloc para p2 es: %p\n", p2);
}
```

Salida

```
La direccion de la memoria reservada por malloc para p1 es: 0x55c3d851b2a0
La direccion de la memoria reservada por malloc para p2 es: 0x55c3d851b740
```

Caso 4
{: .label .label-purple }

De igual forma, si la memoria solicitada para p2 es bastante menos que la
que se había reservado para p1, malloc reservará un nuevo chunk para p2.

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
  void *p1, *p2;

  p1 = malloc(128);

  printf("La direccion de la memoria reservada por malloc para p1 es: %p\n", p1);

  free(p1); // Liberando memoria de p1

  p2 = malloc(120);
  
  printf("La direccion de la memoria reservada por malloc para p2 es: %p\n", p2);
}
```

Salida

```
La direccion de la memoria reservada por malloc para p1 es: 0x55a7c6d812a0
La direccion de la memoria reservada por malloc para p2 es: 0x55a7c6d81740
```
