#include <stdio.h>
#include <unistd.h>

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void leerFlag(char *buf) {
  FILE *fptr;
  fptr = fopen("flag.txt", "r");
  fgets(buf, 31, fptr);
  fclose(fptr); 
}

void vuln() {
  char buf2[32];
  unsigned int barrera = 0;
  char buf1[8];

  leerFlag(buf2);

  printf("Ingresa tu input: ");
  read(1, buf1, 8);

  puts("Hay una barrera que se interpone entre tu input y la flag");

  printf("Escoge el valor de la barrera: ");
  scanf("%u", &barrera);

  printf("Este fue tu input: %s\n", buf1);
  puts("Lograste ver la flag?");
}

int main() {
  setup();
  vuln();
  return 0;
}
