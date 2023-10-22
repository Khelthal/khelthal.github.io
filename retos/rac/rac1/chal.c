#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define THREADS_COUNT 2

typedef struct {
  char* username;
  int logueado;
} userData;

userData DATOS_USUARIO;

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void iniciarDatosUsuario() {
  DATOS_USUARIO.username = (char *) malloc(128);
  DATOS_USUARIO.logueado = 0;
}

void leerDatosUsuario() {
  printf("Ingresa tu nombre de usuario: ");
  scanf("%127s", DATOS_USUARIO.username);
}

void *iniciarSesion() {
  if (strcmp(DATOS_USUARIO.username, "admin") == 0) {
    puts("No puedes ingresar como el usuario admin");
    pthread_exit(NULL);
  }

  sleep(1);
  DATOS_USUARIO.logueado = 1;
  pthread_exit(NULL);
}

void *cambiarUsuario() {
  leerDatosUsuario();
  DATOS_USUARIO.logueado = 0;

  pthread_exit(NULL);
}

void vuln() {
  pthread_t threads[THREADS_COUNT];
  iniciarDatosUsuario();

  leerDatosUsuario();

  pthread_create(&threads[0], NULL, iniciarSesion, NULL);
  pthread_create(&threads[1], NULL, cambiarUsuario, NULL);

  for (int i = 0; i < THREADS_COUNT; i++) {
    pthread_join(threads[i], NULL);
  }

  if (DATOS_USUARIO.logueado && strcmp(DATOS_USUARIO.username, "admin") == 0) {
    puts("Como lograste ser admin??");
  } else {
    puts("Mejor suerte la proxima");
  }
}

int main() {
  setup();
  vuln();
  return 0;
}
