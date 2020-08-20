//Copyright ©2019-2020 Francisco Blas Izquierdo Riera (klondike)

#ifndef MMDB_INTERNAL_H
#define MMDB_INTERNAL_H
#define MMDB_THREADSAFE 1
//Needed to allow 64-bit seeks
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#endif
#include <stdint.h>
#include <stdio.h>

//TODO do some thread safety
//https://stackoverflow.com/questions/766477/are-there-equivalents-to-pread-on-different-platforms

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


//Windows is a bit special here
#define fseeko(a,b,c) _fseeki64((a),(b),(c))
#define ftello(a) _ftelli64((a))

typedef __int64 poff64_t;
typedef int pfilehdl_t;

inline static pfilehdl_t _mm_open(const char *path) {
  return _open(path,_O_RDONLY|_O_BINARY|_O_RANDOM);
}

inline static int _mm_open_err(pfilehdl_t fd) {
  return ((fd) < 0);
}

inline static int _mm_close(pfilehdl_t fd) {
  return _close(fd);
}

inline static size_t _mm_pread(pfilehdl_t fd, void *ret, const size_t sz, poff64_t *offset) {
  HANDLE fhdl = (HANDLE)_get_osfhandle(fd);
  if (fhdl == INVALID_HANDLE_VALUE)
    return 0;
  OVERLAPPED overlapped;
  memset(&overlapped, 0, sizeof(OVERLAPPED));
  overlapped.OffsetHigh = (uint32_t)(*offset >> 32);
  overlapped.Offset = (uint32_t)*offset;
  DWORD rdsz;
  SetLastError(0);
  if (!ReadFile(fhdl, ret, sz, &rdsz, &overlapped) && GetLastError() != ERROR_HANDLE_EOF) {
      errno = GetLastError();
      return 0;
  }  
  *offset += rdsz;
  return rdsz;
}

inline static poff64_t _mm_getfsz(pfilehdl_t fd) {
  return _filelengthi64(fd);
}

#elif defined(MMDB_USE_MMAP) && defined(__unix)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


typedef off_t poff64_t;
struct mmaphdl {
  poff64_t dbsz;
  char *db;
};
typedef struct mmaphdl * pfilehdl_t;

inline static pfilehdl_t _mm_open(const char *path) {
  struct mmaphdl * rv = malloc(sizeof(struct mmaphdl));
  if (rv == NULL)
    goto close0;
  int fd = open(path,O_RDONLY);
  if (fd < 0)
    goto close1;
  struct stat stb;
  if (fstat(fd, &stb) < 0)
    goto close2;
  rv->dbsz = stb.st_size;
  rv->db=mmap(NULL,rv->dbsz,PROT_READ,MAP_SHARED,fd,0);
  if(rv->db == MAP_FAILED)
    goto close2;
  close(fd);
  return rv;
close2:
  close(fd);
close1:
  free(rv);
close0:
  return NULL;
}

inline static int _mm_open_err(pfilehdl_t fd) {
  return (fd == NULL);
}

inline static int _mm_close(pfilehdl_t fd) {
  int rv = munmap(fd->db,fd->dbsz);
  free(fd);
  return rv;
}

inline static size_t _mm_pread(pfilehdl_t fd, void *ret, const size_t sz, poff64_t *offset) {
  poff64_t rv = sz;
  if (*offset >= fd->dbsz)
    return 0;
  if (*offset < 0)
    *offset = 0;
  if (fd->dbsz - *offset < rv)
    rv = fd->dbsz - *offset;
  memcpy(ret,fd->db+(*offset),rv);
  *offset += rv;
  return rv;
}

inline static poff64_t _mm_getfsz(pfilehdl_t fd) {
  return fd->dbsz;
}

#elif defined(__unix)

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


typedef off_t poff64_t;
typedef int pfilehdl_t;

inline static pfilehdl_t _mm_open(const char *path) {
  return open(path,O_RDONLY);
}

inline static int _mm_open_err(pfilehdl_t fd) {
  return ((fd) < 0);
}

inline static int _mm_close(pfilehdl_t fd) {
  return close(fd);
}

inline static size_t _mm_pread(pfilehdl_t fd, void *ret, const size_t sz, poff64_t *offset) {
  ssize_t rv = pread(fd, ret, sz, *offset);
  if (rv < 0)
    return 0;
  *offset += rv; 
  return rv;
}

inline static poff64_t _mm_getfsz(pfilehdl_t fd) {
  struct stat stb;
  if (fstat(fd, &stb) < 0)
    return -1;
  else
    return stb.st_size;
}

#else
//These aren't thread safe!
#warning "Using non thread safe file accessors"
#undef MMDB_THREADSAFE
#define MMDB_THREADSAFE 0

typedef off_t poff64_t;
typedef FILE * pfilehdl_t;

inline static pfilehdl_t _mm_open(const char *path) {
  return fopen(path,"rb");
}

inline static int _mm_open_err(pfilehdl_t fd) {
  return ((fd) == NULL);
}

inline static int _mm_close(pfilehdl_t fd) {
  return fclose(fd);
}

inline static size_t _mm_pread(pfilehdl_t fd, void *ret, const size_t sz, poff64_t *offset) {
  size_t rv;
  if (fseeko(fd, *offset, SEEK_SET) < 0)
    return 0;
  rv = fread(ret, 1, sz, fd);
  *offset += rv; 
  return rv;
}

inline static poff64_t _mm_getfsz(pfilehdl_t fd) {
  if (fseeko(fd, 0, SEEK_END ) < 0)
    return -1;
  return ftello(fd);
}
#endif

#define fread_full(fp,ret,sz,off) (_mm_pread((fp),(ret),(sz),(off)) == (sz))
#define freadc(fp,ret,off) (_mm_pread((fp),(ret),sizeof(char),(off)) == sizeof(char))
#define freadu8(fp,ret,off) (_mm_pread((fp),(ret),sizeof(uint8_t),(off)) == sizeof(uint8_t))

//TODO: mutex handling
struct mmdb_t {
  poff64_t data;
  poff64_t metadata;
  pfilehdl_t fd;
  uint32_t max_depth;
  uint32_t node_count;
  uint16_t record_size;
  uint16_t ip_version;
};

union mmdb_length_ptr {
  mmdb_length_t length;
  mmdb_ptr_t ptr;
};

#endif
