//Copyright ©2019-2020 Francisco Blas Izquierdo Riera (klondike)

#include "mmdb.h"
#include "mmdb_internal.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

//This is a purposefully slow implementation for memory constrained environments

/* This is the most memory efficient way to get the metadata when using an fd based approach. There are faster ways when using a memory mapped database */
static inline poff64_t mmdb_metadata_pos(const mmdb_t * const db) {
  // The maximum allowable size for the metadata section, including the marker that starts the metadata, is 128KiB.
  poff64_t pos = _mm_getfsz(db->fd);
  if (pos < 0)
    return -1;
  // Rewind up to 128KiB backwards
  pos = pos < 128 * 1024 ? 0 : pos - (128 * 1024);
  const char * const match = "\xab\xcd\xefMaxMind.com";
  const char * cur_match = match;
  poff64_t mdata_pos = -1;
  for (char c; freadc(db->fd,&c,&pos) ;) {
    //This only works because \xab only happpens at the beggining of the matched string
    if (c != *cur_match) {
      //Restart matching again
      cur_match = match;
    }
    //We may or may not have restarted matching here so don't else this
    if( c == *cur_match ) {
      //Check the next character
      cur_match ++;
      // Finished matching
      // We can put this here because we know we will never get an empty string as match
      if (!*cur_match) {
        mdata_pos = pos;
        //Restart search
        cur_match = match;
      }
    }
  }
  return mdata_pos;
}

static void _mmdb_type_free(mmdb_type_t * const data) {
  if (data == NULL)
    return;
  switch (data->type) {
    case MMDB_STRING:
      free(data->data.u_string.data);
      break;
    case MMDB_BYTES:
      free(data->data.u_bytes.data);
      break;
    case MMDB_ARRAY:
      for (int i = 0; i < data->data.u_array.length; i++)
        _mmdb_type_free(data->data.u_array.entries+i);
      free(data->data.u_array.entries);
      break;
    case MMDB_MAP:
      for (int i = 0; i < data->data.u_map.length; i++) {
        free(data->data.u_map.keys[i].data);
        _mmdb_type_free(data->data.u_map.values+i);
      }
      free(data->data.u_map.keys);
      free(data->data.u_map.values);
      break;
    default:
      break;
  }
}

//Returns the type of data and the length in the database
//For pointers it returns the position of the pointee instead of the length
static inline int _mmdb_get_type_length(const mmdb_t * const db, enum mmdb_type_enum * const type, union mmdb_length_ptr * const length, poff64_t *pos) {

  //Since pointers aren't extended types the maximum amount to read is 5 bytes
#define max_data_length 5
  uint8_t data[max_data_length];
  // nb counts the number of bytes still unused in the buffer
  poff64_t opos = *pos;
  size_t nb = _mm_pread(db->fd,data,max_data_length,pos);
  size_t onb = nb;
  if (nb <= 0)
    return 1;
  nb--;
  enum mmdb_type_enum rtype = (data[0] >> 5) & 0x7;

  //Pointers are special
  if (rtype == MMDB_POINTER) {
    int psz = ((data[0] >> 3) & 0x3)+1;
    if (nb < psz)
      return 1;
    nb -= psz;
    uint8_t *s = data +1;
    mmdb_ptr_t rptr = data[0] & 0x7;
    switch (psz) {
      case 4:
        rptr = 0;
        for (int i = 0; i < 4; i++) {
          rptr = (rptr << 8) | s[i];
        }
        break;
      case 3:
        // The double rotation will make it 526336
        rptr = (rptr << 8) + *s++ + 8;
      case 2:
        // The rotation will make it 2048
        rptr = (rptr << 8) + *s++ + 8;
      case 1:
        rptr = (rptr << 8) + *s++;
    }
    if (length)
      length->ptr = rptr;
  } else {
    uint8_t * s;
    //Extended type
    if (rtype == MMDB_EXTENDED) {
      if (nb  == 0)
        return 1;
      nb--;
      uint16_t nt = data[1]+7;
      //Unsupported type
      if (nt >= MMDB_TYPE_MAX)
        return 1;
      rtype = nt;
      s = data + 2;
    } else {
      s = data + 1;
    }

    mmdb_length_t rlength = data[0] & 0x1f;
    //Multi-length data
    if (rlength > 28) {
      int lo = rlength-28;
      if (nb < lo)
        return 1;
      nb -= lo;

      rlength = 0;
      switch (lo) {
        case 3:
          //After the two shifts the one becomes 65536
          rlength += 1 + *s++;
          rlength <<= 8;
        case 2:
          //After the shift the one becomes 256
          rlength += 1 + *s++;
          rlength <<= 8;
        case 1:
          rlength += 29 + *s++;
      }
    }
    if (length)
      length->length = rlength;
  }

  if (type) *type = rtype;

  //Reset the file pointer to the data after the type header
  *pos = opos + (onb-nb);
  return 0;
#undef max_data_length
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

#define read_string(fp,v,blength,off) {\
  (v).length = (blength);\
  (v).data = malloc(sizeof(char)*(v).length+1);\
  if (v.data == NULL)\
    return 1;\
  (v).data[(v).length] = '\0';\
  if (!fread_full(fp, (v).data, sizeof(char)*((v).length), (off))) {\
    free((v).data);\
    return 1;\
  }\
}

#define read_bytes(fp,v,blength,off) {\
  (v).length = (blength);\
  (v).data = malloc(sizeof(uint8_t)*(v).length);\
  if (v.data == NULL)\
    return 1;\
  if (!fread_full(fp, (v).data, sizeof(uint8_t)*((v).length), (off))) {\
    free((v).data);\
    return 1;\
  }\
}

#define read_floating(fp,v,cvt,length,elength,off) {\
  if ((length) != (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  if (!fread_full(fp, vdata, sizeof(uint8_t)*(elength), (off))) \
    return 1;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

#define read_suint(fp,v,cvt,length,elength,off) {\
  if ((length) > (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  for (int i = 0; i < (elength) - (length); i++)\
    vdata[i] = 0;\
  if ((length) != 0 && !fread_full(fp, vdata+((elength) - (length)), sizeof(uint8_t)*(length), (off)))\
    return 1;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

#define read_buint(fp,v,length,elength,off) {\
  if ((length) > (elength))\
    return 1;\
  for (int i = 0; i < (elength) - (length); i++)\
    (v).data[i] = 0;\
  if ((length) != 0 && !fread_full(fp, (v).data+((elength) - (length)), sizeof(uint8_t)*(length), (off)))\
    return 1;\
  to_local_endian((v).data,(elength));\
}


#define read_ssint(fp,v,cvt,length,elength,off) {\
  if ((length) > (elength))\
    return 1;\
  uint8_t vdata[(elength)];\
  memset(vdata,0,elength);\
  if ((length) != 0 && !fread_full(fp, vdata+((elength) - (length)), sizeof(uint8_t)*(length), (off)))\
    return 1;\
  for (int i = 0; i < (elength) - (length); i++)\
    vdata[i] = vdata[(elength) - (length)] & 0x80? 0xff : 0;\
  to_local_endian(vdata,(elength));\
  (v) = *(cvt*)vdata;\
}

//Returns 1 on error and the read data on rv
static int mmdb_read(const mmdb_t * const db, mmdb_type_t * const rv, const bool metadata, const bool dereferencing, const uint32_t depth, poff64_t *pos) {

  //Fail if we exceed the allowable structure nesting depth
  if (depth >= db->max_depth)
    return 1;

  enum mmdb_type_enum te;
  union mmdb_length_ptr tlp;
  if (_mmdb_get_type_length(db, &te, &tlp, pos))
    return 1;

  //Automatically dereference pointers
  if (te == MMDB_POINTER) {
    //Metadata shouldn't have pointers
    if (metadata)
      return 1;
    //Pointers can't point to other pointers
    if (dereferencing)
      return 1;
    poff64_t npos = db->data + (poff64_t)tlp.ptr;
    //Depth isn't increased when following pointers as only one level of indirection is allowed
    return mmdb_read(db,rv,metadata,true,depth,&npos);
  }

  mmdb_length_t tl = tlp.length;
  //We have read the type and the length, proceed accordingly
  union mmdb_type_union tu;
  switch (te) {
    case MMDB_BOOL:
      if ( tl > 1)
        return 1;
      tu.u_bool = (tl == 1);
      break;
    case MMDB_STRING:
      read_string(db->fd,tu.u_string,tl,pos);
      break;
    case MMDB_BYTES:
      read_bytes(db->fd,tu.u_bytes,tl,pos);
      break;
    case MMDB_DOUBLE:
      read_floating(db->fd,tu.u_double,mmdb_double_t,tl,8,pos);
      break;
    case MMDB_FLOAT:
      read_floating(db->fd,tu.u_float,mmdb_float_t,tl,4,pos);
      break;
    case MMDB_UINT16:
      read_suint(db->fd,tu.u_uint16,mmdb_uint16_t,tl,2,pos);
      break;
    case MMDB_UINT32:
      read_suint(db->fd,tu.u_uint32,mmdb_uint32_t,tl,4,pos);
      break;
    case MMDB_UINT64:
      read_buint(db->fd,tu.u_uint64,tl,8,pos);
      break;
    case MMDB_UINT128:
      read_buint(db->fd,tu.u_uint128,tl,16,pos);
      break;
    case MMDB_INT32:
      read_ssint(db->fd,tu.u_int32,mmdb_uint32_t,tl,4,pos);
      break;
    case MMDB_ARRAY:
      tu.u_array.length = tl;
      tu.u_array.entries = tu.u_array.length > 0 ? malloc(sizeof(mmdb_type_t)*tu.u_array.length) : NULL;
      if (tu.u_array.length > 0 && tu.u_array.entries == NULL)
        return 1;

      for (mmdb_length_t i = 0; i < tu.u_array.length; i++) {
        if (mmdb_read(db,tu.u_array.entries+i,metadata,false,depth+1,pos) != 0) {
          for (mmdb_length_t j = 0; j < i; j++)
            _mmdb_type_free(tu.u_array.entries+j);
          free(tu.u_array.entries);
          return 1;
        }
      }
      break;
    case MMDB_MAP:
      tu.u_map.length = tl;
      tu.u_map.keys = tu.u_map.length > 0 ? malloc(sizeof(mmdb_string_t)*tu.u_map.length) : NULL;
      if (tu.u_map.length > 0 && tu.u_map.keys == NULL)
        return 1;
      tu.u_map.values = tu.u_map.length > 0 ? malloc(sizeof(mmdb_type_t)*tu.u_map.length) : NULL;
      if (tu.u_map.length > 0 && tu.u_map.values == NULL) {
        free(tu.u_map.keys);
        return 1;
      }

      for (mmdb_length_t i = 0; i < tu.u_map.length; i++) {
        mmdb_type_t tmp;
        //Keys should always be strings and therefore never have more depth than 1
        if (mmdb_read(db,&tmp,metadata,false,db->max_depth-1,pos) != 0)
          goto map_cleanup;
        //TYPE must always be string for keys
        if (tmp.type != MMDB_STRING) {
          _mmdb_type_free(&tmp);
          goto map_cleanup;
        }
        tu.u_map.keys[i] = tmp.data.u_string;
        if (mmdb_read(db,tu.u_map.values+i,metadata,false,depth+1,pos) != 0) {
          free(tu.u_map.keys[i].data);
          goto map_cleanup;
        }
        if (false) {
map_cleanup:
          for (mmdb_length_t j = 0; j < i; j++) {
            free(tu.u_map.keys[j].data);
            _mmdb_type_free(tu.u_map.values+j);
          }
          free(tu.u_map.keys);
          free(tu.u_map.values);
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
  poff64_t pos = db->metadata;
  //Metadata can't have pointers because we can't know where the data section is when parsing it
  if (mmdb_read (db, rv, true, false, 0, &pos) != 0) {
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
  if (pos >= array->data.u_array.length)
    return NULL;
  return array->data.u_array.entries + pos;
}

mmdb_type_t * mmdb_map_get(const mmdb_type_t * const map, const char * const key, size_t len) {
  if (map->type != MMDB_MAP)
    return NULL;
  for (mmdb_length_t i = 0; i < map->data.u_map.length; i++) {
    if (map->data.u_map.keys[i].length != len)
      continue;
    if(!memcmp(map->data.u_map.keys[i].data, key, len))
      return map->data.u_map.values+i;
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
  rv->fd = _mm_open(path);
  if (_mm_open_err(rv->fd))
    goto fail_cleanup1;
  rv->metadata = mmdb_metadata_pos(rv);
  if (rv->metadata < 0)
    goto fail_cleanup2;
  mmdb_type_t *metadata = mmdb_read_metadata(rv);
  if (metadata == NULL)
    goto fail_cleanup2;
  mmdb_type_t *tmp;
  tmp = mmdb_map_gets(metadata,"binary_format_major_version");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data.u_uint16 != 2)
    goto fail_cleanup3;
  tmp = mmdb_map_gets(metadata,"binary_format_minor_version");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data.u_uint16 != 0)
    fprintf(stderr,"Unsupported minor version\n");
  tmp = mmdb_map_gets(metadata,"record_size");
  if (!tmp || tmp->type != MMDB_UINT16 || tmp->data.u_uint16 > 32 || tmp->data.u_uint16 & 0x3 )
    goto fail_cleanup3;
  rv->record_size = tmp->data.u_uint16;
  tmp = mmdb_map_gets(metadata,"node_count");
  if (!tmp || tmp->type != MMDB_UINT32)
    goto fail_cleanup3;
  rv->node_count = tmp->data.u_uint32;
  rv->data = (poff64_t)(rv->record_size/4) * (poff64_t)(rv->node_count) + (poff64_t) 16;
  tmp = mmdb_map_gets(metadata,"ip_version");
  if (!tmp || tmp->type != MMDB_UINT16)
    goto fail_cleanup3;
  rv->ip_version = tmp->data.u_uint16;
  if ( rv->ip_version != 4 && rv->ip_version != 6)
    goto fail_cleanup3;
  mmdb_type_free(metadata);
  return rv;
  fail_cleanup3:
    mmdb_type_free(metadata);
  fail_cleanup2:
    _mm_close(rv->fd);
  fail_cleanup1:
    free(rv);
    return NULL;
}

void mmdb_set_max_depth(mmdb_t *const db, uint32_t max_depth) {
  db->max_depth = max_depth;
}


static mmdb_type_t * mmdb_lookup(const mmdb_t * const db, const uint8_t * const data, size_t len) {
  poff64_t pos = 0;
  uint32_t node = 0;
  if (db->node_count == 0) //Corner case, no nodes: lookup fails
    return NULL;
  for (size_t i  = 0; i < len; i++)
    for (uint8_t j = 0x80; j > 0 ; j>>=1) {
      bool direction = (data[i]&j) != 0;
      poff64_t bpos = (((poff64_t) node)  * ((poff64_t)2) + (direction? (poff64_t)1 :(poff64_t) 0)) * ((poff64_t) db->record_size);
      pos = bpos / ((poff64_t) 8);
      //Initial partial read
      if (bpos&0x4) {
        uint8_t c;
        if (!freadu8(db->fd, &c, &pos))
          return NULL;
        node = c & 0xf;
      } else {
        node = 0;
      }
      for (uint16_t k = bpos&0x7; k + 8 <= db->record_size; k+=8) {
        uint8_t c;
        if (!freadu8(db->fd, &c, &pos))
          return NULL;
        node = (node << 8) | c;
      }
      //Possible final read
      if (db->record_size & 0x4 && !(bpos&0x4)) {
        //The MSBs are placed on the top 4 bits
        uint8_t c;
        if (!freadu8(db->fd, &c, &pos))
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
        pos = db->data + (poff64_t) (node-16-db->node_count);
        if (mmdb_read(db, rv, false, false, 0, &pos)) {
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
  _mm_close(db->fd);
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
      printf("*%"PRIu32, lr->data.u_ptr);
      return;
    case MMDB_STRING:
      putchar('\"');
      for (mmdb_length_t i = 0; i < lr->data.u_string.length; i++) {
        switch (lr->data.u_string.data[i]) {
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
            if (iscntrl(lr->data.u_string.data[i]))
              printf("\\%03o", lr->data.u_string.data[i]);
            else
              putchar(lr->data.u_string.data[i]);
        }
      }
      putchar('\"');
      return;
    case MMDB_DOUBLE:
      printf("%f",lr->data.u_double);
      return;
    case MMDB_FLOAT:
      printf("%f",lr->data.u_float);
      return;
    case MMDB_BYTES:
      putchar('b');
      putchar('\"');
      for (mmdb_length_t i = 0; i < lr->data.u_bytes.length; i++)
          printf("\\%03o", lr->data.u_bytes.data[i]);
      putchar('\"');
      return;
    case MMDB_UINT16:
      printf("%"PRIu16,lr->data.u_uint16);
      return;
    case MMDB_UINT32:
      printf("%"PRIu32,lr->data.u_uint32);
      return;
    case MMDB_INT32:
      printf("%"PRId32,lr->data.u_int32);
      return;
    case MMDB_UINT64:
      printf("0x");
      for (int i = 8; i > 0; i--)
        printf("%02x",lr->data.u_uint64.data[i]);
      return;
    case MMDB_UINT128:
      printf("0x");
      for (int i = 16; i > 0; i--)
        printf("%02x",lr->data.u_uint128.data[i]);
      return;
    case MMDB_BOOL:
      printf(lr->data.u_bool?"true":"false");
      return;
    case MMDB_ARRAY:
      printf("[ ");
      for (mmdb_length_t i = 0; i < lr->data.u_array.length; i++) {
        mmdb_print(lr->data.u_array.entries+i);
        if (i != lr->data.u_array.length-1)
          printf(", ");
      }
      printf(" ]");
      return;
    case MMDB_MAP:
      printf("{ ");
      for (mmdb_length_t i = 0; i < lr->data.u_map.length; i++) {
        mmdb_type_t key;
        key.type = MMDB_STRING;
        key.data.u_string = lr->data.u_map.keys[i];
        mmdb_print(&key);
        printf(": ");
        mmdb_print(lr->data.u_map.values+i);
        if (i != lr->data.u_map.length -1)
          printf(", ");
      }
      printf(" }");
      return;
  }
}
