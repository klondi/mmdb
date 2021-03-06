//Copyright ©2019-2020 Francisco Blas Izquierdo Riera (klondike)

#ifndef MMDB_H
#define MMDB_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef MMDB_MAX_DEPTH
#define MMDB_MAX_DEPTH 16
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef uint32_t mmdb_length_t;

typedef struct mmdb_t mmdb_t;

enum mmdb_type_enum {
  MMDB_EXTENDED = 0,
  MMDB_POINTER = 1,
  MMDB_STRING = 2,
  MMDB_DOUBLE = 3,
  MMDB_BYTES = 4,
  MMDB_UINT16 = 5,
  MMDB_UINT32 = 6,
  MMDB_MAP = 7,
  MMDB_INT32 = 8,
  MMDB_UINT64 = 9,
  MMDB_UINT128 = 10,
  MMDB_ARRAY = 11,
  MMDB_DATA_CACHE = 12,
  MMDB_END_MARKER = 13,
  MMDB_BOOL = 14,
  MMDB_FLOAT = 15
};

#define MMDB_TYPE_MAX 16

typedef struct mmdb_type_t mmdb_type_t;

typedef double mmdb_double_t;

typedef uint16_t mmdb_uint16_t;
typedef uint32_t mmdb_uint32_t;
typedef uint32_t mmdb_ptr_t;
typedef int32_t mmdb_int32_t;

typedef struct mmdb_uint64_t {
  uint8_t data[8];
} mmdb_uint64_t;

typedef struct mmdb_uint128_t {
  uint8_t data[16];
} mmdb_uint128_t;

typedef bool mmdb_bool_t;

typedef float mmdb_float_t;

typedef struct mmdb_string_t {
  mmdb_length_t length;
  char *data;
} mmdb_string_t;

typedef struct mmdb_bytes_t {
  mmdb_length_t length;
  uint8_t *data;
} mmdb_bytes_t;

//TODO: speed up searches using a hash table or something
typedef struct mmdb_map_t {
  mmdb_string_t *keys;
  mmdb_type_t *values;
  mmdb_length_t length;
} mmdb_map_t;

typedef struct mmdb_array_t {
  mmdb_type_t *entries;
  mmdb_length_t length;
} mmdb_array_t;

union mmdb_type_union {
  mmdb_ptr_t u_ptr;
  mmdb_double_t u_double;
  mmdb_uint16_t u_uint16;
  mmdb_uint32_t u_uint32;
  mmdb_int32_t u_int32;
  mmdb_uint64_t u_uint64;
  mmdb_uint128_t u_uint128;
  mmdb_bool_t u_bool;
  mmdb_float_t u_float;
  mmdb_string_t u_string;
  mmdb_bytes_t u_bytes;
  mmdb_map_t u_map;
  mmdb_array_t u_array;
};

struct mmdb_type_t {
  enum mmdb_type_enum type;
  union mmdb_type_union data;
};


mmdb_t * mmdb_open(const char * path);
void mmdb_set_max_depth(mmdb_t * db, uint32_t max_depth);
mmdb_type_t * mmdb_read_metadata(const mmdb_t * db);
mmdb_type_t * mmdb_lookup4(const mmdb_t * db, const uint8_t ip[4]);
mmdb_type_t * mmdb_lookup6(const mmdb_t * db, const uint8_t ip[16]);
mmdb_type_t * mmdb_array_get(const mmdb_type_t * array, mmdb_length_t pos);
mmdb_type_t * mmdb_map_get(const mmdb_type_t * map, const char * key, size_t len);
mmdb_type_t * mmdb_map_gets(const mmdb_type_t * map, const char * key);
void mmdb_print(const mmdb_type_t * lr);
void mmdb_type_free(mmdb_type_t * data);
void mmdb_close(mmdb_t * db);
int mmdb_threadsafe(void);


#ifdef __cplusplus
}
#endif
#endif
