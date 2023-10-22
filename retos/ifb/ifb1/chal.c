#include <stdio.h>

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
  puts("Ganaste");
}

unsigned char leer_int() {
  unsigned char num;
  scanf("%hhu", &num);
  getchar();
  return num;
}

void vuln() {
  unsigned char cuenta1, cuenta2, transferencia;

  cuenta1 = 127;
  cuenta2 = 127;

  printf("El saldo de tus cuentas es: %d %d\n", cuenta1, cuenta2);

  puts("Ingresa la cantidad a transferir");
  transferencia = leer_int();

  cuenta1 += transferencia;
  cuenta2 -= transferencia;

  printf("El saldo de tus cuentas es: %d %d\n", cuenta1, cuenta2);

  if (cuenta1 == 21 && cuenta2 == 233) {
    win();
  } else {
    puts("Mejor suerte la proxima :)");
  }
}

int main() {
  setup();
  vuln();
  return 0;
}
