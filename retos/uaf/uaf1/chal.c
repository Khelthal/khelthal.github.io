#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char * username;
  char * password;
} usuario;

usuario USUARIOS_REGISTRADOS[] = {
  {.username = "root", .password = NULL},
  {.username = "guest", .password = "guest"},
};

usuario USUARIO_ACTIVO = {
  .username = NULL,
  .password = NULL
};

// Esta funcion solo sirve para que el input y output funcione correctamente al correr
// en docker y no es importante analizarla.
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

int leerInt() {
  int opcion;
  scanf("%d", &opcion);
  getchar();

  return opcion;
}

void inicializarPasswordRoot() {
  FILE *fptr;
  fptr = fopen("flag.txt", "r");

  USUARIOS_REGISTRADOS[0].password = (char *) malloc(128);
  
  fgets(USUARIOS_REGISTRADOS[0].password, 128, fptr);
  fclose(fptr); 
}

int menu() {
  puts("");
  puts("Elige una accion a realizar");
  puts("1. Ingresar username");
  puts("2. Ingresar password");
  puts("3. Validar credenciales");
  puts("4. Limpiar credenciales");
  puts("5. Salir");
  puts("");
  puts(">>");

  return leerInt();
}

int encontrarUsuario(char* username) {
  int comandosValidosLen = sizeof(USUARIOS_REGISTRADOS) / sizeof(usuario);

  for (int i = 0; i < comandosValidosLen; i++) {
    if (strcmp(username, USUARIOS_REGISTRADOS[i].username) == 0) {
      return i;
    }
  }

  return -1;
}

void ingresarUsername() {
  if (!USUARIO_ACTIVO.username)
    USUARIO_ACTIVO.username = (char*) malloc(128);

  puts("Ingresa el nombre de usuario");
  scanf("%127s", USUARIO_ACTIVO.username);
}

void ingresarPassword() {
  if (!USUARIO_ACTIVO.password)
    USUARIO_ACTIVO.password = (char*) malloc(128);

  puts("Ingresa la password");
  scanf("%127s", USUARIO_ACTIVO.password);
}

void validarCredenciales() {
  int indiceUsuario;
  char passwordIngresada[128];

  if (!USUARIO_ACTIVO.username || !USUARIO_ACTIVO.password) {
    puts("Falta ingresar username o password");
    return;
  }

  indiceUsuario = encontrarUsuario(USUARIO_ACTIVO.username);

  if (indiceUsuario == -1) {
    printf("El usuario %s no esta registrado", USUARIO_ACTIVO.username);
    return;
  }

  strcpy(passwordIngresada, USUARIO_ACTIVO.password);
  strcpy(USUARIO_ACTIVO.password, USUARIOS_REGISTRADOS[indiceUsuario].password);

  if (strcmp(USUARIO_ACTIVO.password, passwordIngresada) == 0) {
    printf("Bienvenido %s\n", USUARIO_ACTIVO.username);
  } else {
    printf("Password incorrecta para el usuario %s\n", USUARIO_ACTIVO.username);
    strcpy(USUARIO_ACTIVO.password, passwordIngresada);
  }
}

void limpiarCredenciales() {
  if (USUARIO_ACTIVO.username)
    free(USUARIO_ACTIVO.username);

  if (USUARIO_ACTIVO.password)
    free(USUARIO_ACTIVO.password);

  puts("Se limpiaron las credenciales ingresadas!");
}

void vuln() {
  int opcion;

  while ((opcion = menu()) != 5) {
    switch (opcion) {
      case 1:
        ingresarUsername();
        break; 
      case 2:
        ingresarPassword();
        break; 
      case 3:
        validarCredenciales();
        break; 
      case 4:
        limpiarCredenciales();
        break; 
      default:
        puts("Opcion invalida"); 
    }
  }
}

int main() {
  setup();
  inicializarPasswordRoot();
  vuln();
  return 0;
}
