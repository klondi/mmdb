//Copyright ©2019 Francisco Blas Izquierdo Riera (klondike)

//Needed to allow 64-bit seeks
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200112L
#endif

#include "mmdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#ifdef _WIN32
//Windows is a bit special here
typedef __int64 poff64_t;
#define fseeko(a,b,c) _fseeki64((a),(b),(c))
#else
typedef off_t poff64_t;
#endif

//TODO: mutex handling
struct mmdb_t {
  poff64_t data;
  poff64_t metadata;
  FILE * fd;
  uint32_t max_depth;
  uint32_t node_count;
  uint16_t record_size;
  uint16_t ip_version;
};

//This is a purposefully slow implementation for memory constrained environments


static inline poff64_t mmdb_metadata_pos(const mmdb_t * const db) {
  // The maximum allowable size for the metadata section, including the marker that starts the metadata, is 128KiB.
  const poff64_t mmdb_metadata_pos_max = -128 * 1024;
  
  fseeko( db->fd, mmdb_metadata_pos_max, SEEK_END );
  
  static const unsigned char * const match = (const unsigned char * const) "\xab\xcd\xefMaxMind.com";
  const unsigned char * cur_match = match;
  poff64_t mdata_pos = 0;
  bool matched = false;

  int c;
  
  while ((c = fgetc(db->fd)) != EOF) {
    mdata_pos++;
    //This only works because \xab only happpens at the beggining of the matched string
    if ( c != *cur_match) {
      //Restart matching again
      cur_match = match;
    } 
    //We may or may not have restarted matching here so don't else this
    if( c == *cur_match ) {
      //Check the next character
      cur_match ++;
      // Finished matching
      // We can put this here because we know we will never get an empty string as match
      if (*cur_match == '\0') {
        matched = true;
        mdata_pos = 0;
        //Restart search
        cur_match = match;
      }
    }
  }
  
  if (!matched)
    return -1;
  else
    return mdata_pos;
}

static void _mmdb_type_free(mmdb_type_t * const data) {
  if (data == NULL)
    return;
  switch (data->type) {
    case MMDB_STRING:
      free(data->data._string.data);
      break;
    case MMDB_BYTES:
      free(data->data._bytes.data);
      break;
    case MMDB_ARRAY:
      for (int i = 0; i < data->data._array.length; i++)
        _mmdb_type_free(data->data._array.entries+i);
      free(data->data._array.entries);
      break;
    case MMDB_MAP:
      for (int i = 0; i < data->data._map.length; i++) {
        free(data->data._map.keys[i].data);
        _mmdb_type_free(data->data._map.values+i);
      }
      free(data->data._map.keys);
      free(data->data._map.values);
      break;
    default:
      break;
  }
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define to_local_endian(data, size) {\
  for (int i = 0; i < (size)/2; i++) {\
    uint8_t tmp = (data)[i];\
    (data)[i] = (data)[((size)-1)-i];\
    (data)[((size)-1)-i] = tmp;\
  }\
}
#else
#define to_local_endian(data)
#endif

#define read_string(fp,v,blength) {\
  (v).length = (blength);\
  (v).data = malloc(sizeof(char)*(v).length+1);\
  if (v.data == NULL)\
    return 1;\
  (v).data[(v).length] = '\0';\
  if (fread((v).data, sizeof(char)*((v).length), 1, (fp)) != 1) {\
    free((v).data);\
    return 1;\
  }\
}

#define read_bytes(fp,v,blength) {\
  (v).length = (blength);\
  (v).data = malloc(sizeof(uint8_t)*(v).length);\
  if (v.data == NULL)\
    return 1;\
  if (fread((v).data, sizeof(uint8_t)*((v).length), 1, (fp)) != 1) {\
    free((v).data);\
    return 1;\
  }\
}

#define read_floating(fp,v,cvt,length,elength) {\
  if ((length) != (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  if (fread(vdata, sizeof(uint8_t)*(elength), 1, (fp)) != 1)\
    return 1;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

#define read_suint(fp,v,cvt,length,elength) {\
  if ((length) > (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  for (int i = 0; i < (elength) - (length); i++)\
    vdata[i] = 0;\
  if ((length) != 0 && fread(vdata+((elength) - (length)), sizeof(uint8_t)*(length), 1, (fp)) != 1)\
    return 1;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

#define read_buint(fp,v,length,elength) {\
  if ((length) > (elength))\
    return 1;\
  for (int i = 0; i < (elength) - (length); i++)\
    (v).data[i] = 0;\
  if ((length) != 0 && fread((v).data+((elength) - (length)), sizeof(uint8_t)*(length), 1, (fp)) != 1)\
    return 1;\
  to_local_endian((v).data,(elength));\
}


#define read_ssint(fp,v,cvt,length,elength) {\
  if ((length) > (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  if ((length) != 0 && fread(vdata+((elength) - (length)), sizeof(uint8_t)*(length), 1, (fp)) != 1)\
    return 1;\
  for (int i = 0; i < (elength) - (length); i++)\
    vdata[i] = vdata[(elength) - (length)] & 0x80? 0xff : 0;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

//Returns 1 on error and the read data on rv
static int mmdb_read(const mmdb_t * const db, mmdb_type_t * const rv, const bool metadata, const bool dereferencing, const uint32_t depth) {

  //Fail if we exceed the allowable structure nesting depth
  if (depth >= db->max_depth)
    return 1;

  int fc = fgetc(db->fd);
  if (fc == EOF)
    return 1;
  enum mmdb_type_enum te = (fc >> 5) & 0x7;
  //Extended type
  if (te == MMDB_EXTENDED) {
    int sc = fgetc(db->fd);
    if (sc == EOF)
      return 1;
    sc += 7;
    //Unsupported type
    if (sc >= MMDB_TYPE_MAX)
      return 1;
    te = sc;
  }
  mmdb_length_t tl = fc & 0x1f;
  //Pointers are special
  if (te == MMDB_POINTER) {
    //Metadata shouldn't have pointers
    if (metadata)
      return 1;
    //Pointers can't point to other pointers
    if (dereferencing)
      return 1;
    int psz = (fc >> 3) & 0x3;
    uint8_t tdata[4];
    if (fread(tdata, sizeof(uint8_t)*(psz+1), 1, db->fd) != 1)
      return 1;
    //If the size is 3,[...] the last three bits of the control byte are ignored.
    mmdb_ptr_t pv = (psz == 3? 0: fc & 0x7);
    for (int i = 0; i <= psz; i++) {
      pv = (pv << 8) | tdata[i];
    }
    if (psz == 1)
      pv += 2048;
    else if (psz == 2)
      pv += 526336;
    fpos_t prev;
    fgetpos(db->fd,&prev);
    fseeko( db->fd, db->data + (poff64_t)pv, SEEK_SET );
    //Depth isn't increased when following pointers as only one level of indirection is allowed
    int readval = mmdb_read(db,rv,metadata,true,depth);
    fsetpos(db->fd,&prev);
    return readval;
  } else if (tl >= 29) {
    uint8_t tdata[3];
    if (fread(tdata, sizeof(uint8_t)*(tl-28), 1, db->fd) != 1)
      return 1;
    mmdb_length_t ttl=0;
    for (int i = 0; i < tl-28; i++) {
      ttl = (ttl << 8) | tdata[i];
    }
    if (tl == 29)
      tl = ttl + 29;
    else if (tl == 30)
      tl = ttl + 285;
    else if (tl == 31)
      tl = ttl + 65821;
  }
  //We have read the type and the length, proceed accordingly
  union mmdb_type_union tu;
  switch (te) {
    case MMDB_BOOL:
      if ( tl > 1)
        return 1;
      tu._bool = (tl == 1);
      break;
    case MMDB_STRING:
      read_string(db->fd,tu._string,tl);
      break;
    case MMDB_BYTES:
      read_bytes(db->fd,tu._bytes,tl);
      break;
    case MMDB_DOUBLE:
      read_floating(db->fd,tu._double,mmdb_double_t,tl,8);
      break;
    case MMDB_FLOAT:
      read_floating(db->fd,tu._float,mmdb_float_t,tl,4);
      break;
    case MMDB_UINT16:
      read_suint(db->fd,tu._uint16,mmdb_uint16_t,tl,2);
      break;
    case MMDB_UINT32:
      read_suint(db->fd,tu._uint32,mmdb_uint32_t,tl,4);
      break;
    case MMDB_UINT64:
      read_buint(db->fd,tu._uint64,tl,8);
      break;
    case MMDB_UINT128:
      read_buint(db->fd,tu._uint128,tl,16);
      break;
    case MMDB_INT32:
      read_ssint(db->fd,tu._uint32,mmdb_uint32_t,tl,4);
      break;
    case MMDB_ARRAY:
      tu._array.length = tl;
      tu._array.entries = tu._array.length > 0 ? malloc(sizeof(mmdb_type_t)*tu._array.length) : NULL;
      if (tu._array.length > 0 && tu._array.entries == NULL)
        return 1;
      
      for (mmdb_length_t i = 0; i < tu._array.length; i++) {
        if (mmdb_read(db,tu._array.entries+i,metadata,false,depth+1) != 0) {
          for (mmdb_length_t j = 0; j < i; j++)
            _mmdb_type_free(tu._array.entries+j);
          free(tu._array.entries);
          return 1;
        }
      }
      break;
    case MMDB_MAP:
      tu._map.length = tl;
      tu._map.keys = tu._map.length > 0 ? malloc(sizeof(mmdb_string_t)*tu._map.length) : NULL;
      if (tu._map.length > 0 && tu._map.keys == NULL)
        return 1;
      tu._map.values = tu._map.length > 0 ? malloc(sizeof(mmdb_type_t)*tu._map.length) : NULL;
      if (tu._map.length > 0 && tu._map.values == NULL) {
        free(tu._map.keys);
        return 1;
      }
      
      for (mmdb_length_t i = 0; i < tu._map.length; i++) {
        mmdb_type_t tmp;
        //Keys should always be strings and therefore never have more depth than 1
        if (mmdb_read(db,&tmp,metadata,false,db->max_depth-1) != 0)
          goto map_cleanup;
        //TYPE must always be string for keys
        if (tmp.type != MMDB_STRING) {
          _mmdb_type_free(&tmp);
          goto map_cleanup;
        }
        tu._map.keys[i] = tmp.data._string;
        if (mmdb_read(db,tu._map.values+i,metadata,false,depth+1) != 0) {
          free(tu._map.keys[i].data);
          goto map_cleanup;
        }
        if (false) {
map_cleanup:
          for (mmdb_length_t j = 0; j < i; j++) {
            free(tu._map.keys[j].data);
            _mmdb_type_free(tu._map.values+j);
          }
          free(tu._map.keys);
          free(tu._map.values);
          return 1;
        }
      }
      break;
    case MMDB_POINTER:
    case MMDB_EXTENDED:
    case MMDB_DATA_CACHE:
    case MMDB_END_MARKER:
      //These should not happen with this API
      return 1;
  }
  rv->type = te;
  rv->data = tu;
  return 0;
}

#undef to_local_endian
#undef read_bytes
#undef read_floating
#undef read_suint
#undef read_buint
#undef read_ssint

void mmdb_type_free(mmdb_type_t * const data) {
  if (data == NULL)
    return;
  _mmdb_type_free(data);
  free(data);
}

//Return value: NULL on error, a pointer to the metadata struct otherwise
mmdb_type_t * mmdb_read_metadata(const mmdb_t * const db) {
  mmdb_type_t * rv = malloc(sizeof(mmdb_type_t));
  if (rv == NULL)
    return NULL;
  fseeko( db->fd, db->metadata, SEEK_END );
  //Metadata can't have pointers because we can't know where the data section is when parsing it
  if (mmdb_read (db, rv, true, false, 0) != 0) {
    free(rv);
    return NULL;
  }
  if (rv->type != MMDB_MAP) {
    mmdb_type_free(rv);
    return NULL;
  }
  return rv;
}

mmdb_type_t * mmdb_array_get(const mmdb_type_t * const array, mmdb_length_t pos) {
  if (array->type != MMDB_ARRAY)
    return NULL;
  if (pos >= array->data._array.length)
    return NULL;
  return array->data._array.entries + pos;
}

mmdb_type_t * mmdb_map_get(const mmdb_type_t * const map, const char * const key, size_t len) {
  if (map->type != MMDB_MAP)
    return NULL;
  for (mmdb_length_t i = 0; i < map->data._map.length; i++) {
    if (map->data._map.keys[i].length != len)
      continue;
    if(!memcmp(map->data._map.keys[i].data, key, len))
      return map->data._map.values+i;
  }
  return NULL;
}

mmdb_type_t * mmdb_map_gets(const mmdb_type_t * const map, const char * const key) {
  if (map->type != MMDB_MAP)
    return NULL;
  return mmdb_map_get(map, key, strlen(key));
}

mmdb_t * mmdb_open(const char * const path) {
  mmdb_t *rv = malloc(sizeof(mmdb_t));
  if (rv == NULL)
    return NULL;
  rv->max_depth = MMDB_MAX_DEPTH;
  rv->fd = fopen(path,"rb");
  if (rv->fd == NULL)
    goto fail_cleanup1;
  rv->metadata = -mmdb_metadata_pos(rv);
  if (rv->metadata > 0)
    goto fail_cleanup2;
  mmdb_type_t *metadata = mmdb_read_metadata(rv);
  if (metadata == NULL)
    goto fail_cleanup2;
  mmdb_type_t *tmp;
  tmp = mmdb_map_gets(metadata,"binary_format_major_version");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data._uint16 != 2)
    goto fail_cleanup3;
  tmp = mmdb_map_gets(metadata,"binary_format_minor_version");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data._uint16 != 0)
    fprintf(stderr,"Unsupported minor version\n");
  tmp = mmdb_map_gets(metadata,"record_size");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data._uint16 > 32 || tmp->data._uint16 & 0x3 )
    goto fail_cleanup3;
  rv->record_size = tmp->data._uint16;
  tmp = mmdb_map_gets(metadata,"node_count");
  if (!tmp || tmp->type != MMDB_UINT32)
    goto fail_cleanup3;
  rv->node_count = tmp->data._uint32;
  rv->data = (poff64_t)(rv->record_size/4) * (poff64_t)(rv->node_count) + (poff64_t) 16;  
  printf("%ld\n",rv->data);
  tmp = mmdb_map_gets(metadata,"ip_version");
  if (!tmp || tmp->type != MMDB_UINT16)
    goto fail_cleanup3;
  rv->ip_version = tmp->data._uint16;
  if ( rv->ip_version != 4 && rv->ip_version != 6) 
    goto fail_cleanup3;
  fseeko(rv->fd,rv->data-16,SEEK_SET);
  for (int i = 0; i < 16; i++)
    if (fgetc(rv->fd) != 0)
      printf("Invalid header! %d\n",i);
  mmdb_type_free(metadata);
  return rv;
  fail_cleanup3:
    mmdb_type_free(metadata);
  fail_cleanup2:
    fclose(rv->fd);
  fail_cleanup1:
    free(rv);
    return NULL;
}

void mmdb_set_max_depth(mmdb_t *const db, uint32_t max_depth) {
  db->max_depth = max_depth;
}


static mmdb_type_t * mmdb_lookup(const mmdb_t * const db, const uint8_t * const data, size_t len) {
  uint32_t node = 0;
  if (db->node_count == 0) //Corner case, no nodes: lookup fails
    return NULL;
  for (size_t i  = 0; i < len; i++)
    for (uint8_t j = 0x80; j > 0 ; j>>=1) {
      bool direction = (data[i]&j) != 0;
      poff64_t bpos = (((poff64_t) node)  * ((poff64_t)2) + (direction? (poff64_t)1 :(poff64_t) 0)) * ((poff64_t) db->record_size);
      fseeko(db->fd, bpos / ((poff64_t) 8), SEEK_SET);
      //Initial partial read
      if (bpos&0x4) {
        int c = fgetc(db->fd);
        if (c == EOF)
          return NULL;
        node = c & 0xf;
      } else {
        node = 0;
      }
      for (uint16_t k = bpos&0x7; k + 8 <= db->record_size; k+=8) {
        int c = fgetc(db->fd);
        if (c == EOF)
          return NULL;
        node = (node << 8) | c;
      }
      //Possible final read
      if (db->record_size & 0x4 && !(bpos&0x4)) {
        //The MSBs are placed on the top 4 bits
        int c = fgetc(db->fd);
        if (c == EOF)
          return NULL;
        node |= ((c&0xf0u) >> 4) << (db->record_size-4);
      }
      if(node == db->node_count) //If the record value is equal to the number of nodes, that means that we do not have any data for the IP address, and the search ends here.
        return NULL;
      else if (node > db->node_count) {
        if (node < db->node_count +16) //This has the side effect that record values $node_count + 1 through $node_count + 15 inclusive are not valid
          return NULL;
        mmdb_type_t * rv = malloc(sizeof(mmdb_type_t));
        if (rv == NULL)
          return NULL;
        fseeko(db->fd, db->data + (poff64_t) (node-16-db->node_count), SEEK_SET);
        if (mmdb_read(db, rv, false, false, 0)) {
          free(rv);
          return NULL;
        } else
          return rv;
      }
    }
  return NULL;
}

mmdb_type_t * mmdb_lookup4(const mmdb_t * const db, const uint8_t * const ip) {
  if (db->ip_version == 4)
    return mmdb_lookup(db, ip, 4);
  else { //db->ip_version == 6
    // When storing IPv4 addresses in an IPv6 tree, they are stored as-is, so they occupy the first 32-bits of the address space (from 0 to 2**32 - 1).
    uint8_t data[16];
    for (int i = 0; i < 12; i++)
      data[i] = 0;
    for (int i = 0; i < 4; i++)
      data[12+i] = ip[i];
    return mmdb_lookup(db, data, 16);
  }
}

mmdb_type_t * mmdb_lookup6(const mmdb_t * const db, const uint8_t * const ip) {
  if (db->ip_version == 4)
    return NULL; //Lookup always fails
  else //db->ip_version == 6
    return mmdb_lookup(db, ip, 16);
}


void mmdb_close(mmdb_t * const db) {
  fclose(db->fd);
  free(db);
}

void mmdb_print(const mmdb_type_t * const lr) {
  if (lr == NULL) {
    printf("nil");
    return;
  }
  switch(lr->type) {
    case MMDB_EXTENDED:
      printf("INVALID_EXTENDED");
      return;
    case MMDB_DATA_CACHE:
      printf("DATA_CACHE");
      return;
    case MMDB_END_MARKER:
      printf("END_MARKER");
      return;
    case MMDB_POINTER:
      printf("*%"PRIu32, lr->data._ptr);
      return;
    case MMDB_STRING:
      putchar('\"');
      for (mmdb_length_t i = 0; i < lr->data._string.length; i++) {
        switch (lr->data._string.data[i]) {
          case '\"':
            printf("\\\"");
            break;
          case '\'':
            printf("\\\'");
            break;
          case '\\':
            printf("\\\\");
            break;
          case '\a':
            printf("\\a");
            break;
          case '\b':
            printf("\\b");
            break;
          case '\n':
            printf("\\n");
            break;
          case '\t':
            printf("\\t");
            break;
          // and so on
          default:
            if (iscntrl(lr->data._string.data[i]))
              printf("\\%03o", lr->data._string.data[i]);
            else
              putchar(lr->data._string.data[i]);
        }
      }
      putchar('\"');
      return;
    case MMDB_DOUBLE:
      printf("%f",lr->data._double);
      return;
    case MMDB_FLOAT:
      printf("%f",lr->data._float);
      return;
    case MMDB_BYTES:
      putchar('b');
      putchar('\"');
      for (mmdb_length_t i = 0; i < lr->data._bytes.length; i++)
          printf("\\%03o", lr->data._bytes.data[i]);
      putchar('\"');
      return;
    case MMDB_UINT16:
      printf("%"PRIu16,lr->data._uint16);
      return;
    case MMDB_UINT32:
      printf("%"PRIu32,lr->data._uint32);
      return;
    case MMDB_INT32:
      printf("%"PRId32,lr->data._int32);
      return;
    case MMDB_UINT64:
      printf("0x");
      for (int i = 8; i > 0; i--)
        printf("%02x",lr->data._uint64.data[i]);
      return;
    case MMDB_UINT128:
      printf("0x");
      for (int i = 16; i > 0; i--)
        printf("%02x",lr->data._uint128.data[i]);
      return;
    case MMDB_BOOL:
      printf(lr->data._bool?"true":"false");
      return;
    case MMDB_ARRAY:
      printf("[ ");
      for (mmdb_length_t i = 0; i < lr->data._array.length; i++) {
        mmdb_print(lr->data._array.entries+i);
        if (i != lr->data._array.length-1)
          printf(", ");
      }
      printf(" ]");
      return;
    case MMDB_MAP:
      printf("{ ");
      for (mmdb_length_t i = 0; i < lr->data._map.length; i++) {
        mmdb_type_t key;
        key.type = MMDB_STRING;
        key.data._string = lr->data._map.keys[i];
        mmdb_print(&key);
        printf(": ");
        mmdb_print(lr->data._map.values+i);
        if (i != lr->data._map.length -1)
          printf(", ");
      }
      printf(" }");
      return;
  }
}
