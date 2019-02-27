//Copyright ©2019 Francisco Blas Izquierdo Riera (klondike)

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "mmdb.h"

int main (int argc, const char * const * const argv) {
  if (argc < 3) {
    printf("Usage: %s database ip...\n",argv[0]);
    return 1;
  }
  mmdb_t *db = mmdb_open(argv[1]);

  if (db == NULL) {
    printf("Failed to open DB\n");
    return 1;
  }

  struct in6_addr bip6;
  struct in_addr bip4;

  for (int i = 2; i < argc; i++) {
    mmdb_type_t *lr;
    if(inet_pton(AF_INET, argv[i], &bip4))
      lr = mmdb_lookup4(db, (uint8_t *)&bip4);
    else if (inet_pton(AF_INET6, argv[i], &bip6))
      lr = mmdb_lookup6(db, (uint8_t *)&bip6);
    else {
      printf("Invalid IP address %s\n", argv[i]);
      continue;
    }
    if (lr) {
      mmdb_print(lr);
      putchar('\n');
      mmdb_type_free(lr);
    } else {
      printf("Lookup Failed!\n");
    }
  }
  mmdb_close(db);
  return 0;
}
