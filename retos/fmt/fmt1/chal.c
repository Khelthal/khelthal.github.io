#include <stdio.h>

char* WIN = "flag{lograste_imprimir_el_contenido}";

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
  char buf[32];
  scanf("%31s", buf);

  printf(buf);
}

int main() {
  setup();
  puts("En este reto debes lograr utilizar el format string para imprimir la variable WIN");
  printf("Aqui esta la direccion del string en la variable WIN: %p\n", WIN);
  vuln();
  return 0;
}
