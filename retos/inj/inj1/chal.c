#include <stdio.h>

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void win(int a, int b, int c, int d) {
  if (a == 0xdead && b == 0xbeef && c == 0xcafe && d == 0xbabe) {
    puts("Ganaste");
  } else {
    puts("Intenta con un shellcode");
  }
}

void vuln() {
  char buf[256];
  printf("%p\n", buf);

  gets(buf);
}

int main() {
  setup();
  puts("Consejo 1: Revisa la arquitectura del binario");
  puts("Consejo 2: Busca como pasar argumentos a una funcion en la arquitectura del binario");
  vuln();
  return 0;
}
