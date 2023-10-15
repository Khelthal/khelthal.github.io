#include <stdio.h>

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void win(int a) {
  if (a == 1) {
    puts("Ganaste");
  } else {
    printf("El valor de a es %d.\n", a);
  }
}

void vuln() {
  char buf[24];
  scanf("%s", buf);
}

int main() {
  setup();
  puts("Consejo 1: Revisa la arquitectura del binario");
  puts("Consejo 2: Busca como pasar argumentos a una funcion en la arquitectura del binario");
  vuln();
  return 0;
}
