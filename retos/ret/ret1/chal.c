#include <stdio.h>

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
  puts("Ingresa input:");
  char buf[16];
  gets(buf);
}

int main() {
  setup();
  vuln();
  return 0;
}
