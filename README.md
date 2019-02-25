# MMDB
A simple parser and lookup library for MaxMind DB files

## License
MMDB is licensed under GNU's GPLv2 or, at your choice, any later version.

## Copyright
MMDB is Copyright © 2019 Francisco Blas Izquierdo Riera (klondike)

## Summary
MMDB started as a weekend project in order to fill the licensing gap provided by the
official MaxMind DB libraries provided by MaxMind. These libraries are licensed under the
Apache2.0 license and can't, therefore, be used with GPLv2 software.

MMDB is designed to be reasonably small at only around 800 lines of code (yeah, the 
format is a bit complex). It tries to keep the memory (virtual and physical) fingerprint
low, so it will not try to mmap the DB files or anything similar, instead it will use
the "portable" C file API in order to access the file using fseek calls to jump to the
right place in the file. Sadly 64-bit support for fseek isn't portable, mmdb tries to
solve that providing a small shim at compilation time emulating fseeko for Windows
platforms although it hasn't been well tested.

MMDB was implemented exclusively following the specification at
https://maxmind.github.io/MaxMind-DB/ and using MaxMind's GeoLite databases to test the
implementation. This approach was chosen to ensure the GPL licensed code is clean from
Apache2.0 code.

## Usage
MMDB provides a simple API. It currently has no dependencies and can be easily integrated
into your own GPL project.

### Database object structure
`mmdb_type_t`  

All returned database objects are of type `mmdb_type_t`, this object contains an `mmdb_type_enum`
called `type` with the specific type of object and a `mmdb_type_union` called `data` with the
specific data structure.

All objects are presented with an alias to an equivalent C99 type (when possible) and in the endian
exposed at compile time.

Below the most common types are described but you can always check the mmdb.h file for extra
details. In general you should consider any type not described here as a hint that the database
may be inconsistent or a bug may exist in this software.

#### Booleans
`mmdb_bool_t`  
`MMDB_BOOL`  
`_bool`  

Booleans can be either true or false.
Their type is `mmdb_bool_t`, their `mmdb_type_enum` value is `MMDB_BOOL`  and their
`mmdb_type_union` member is called `_bool`.

#### Doubles preccission floating point numbers (doubles)
`mmdb_double_t`  
`MMDB_DOUBLE`  
`_double`  

Doubles represent an IEEE 754 double precission floating point number.
Their type is `mmdb_double_t`, their `mmdb_type_enum` value is `MMDB_DOUBLE` and their
`mmdb_type_union` member is called `_double`.

#### Single preccission floating point numbers (floats)
`mmdb_float_t`  
`MMDB_FLOAT`  
`_float`  

Floats represent an IEEE 754 single precission floating point number.
Their type is `mmdb_float_t`, their `mmdb_type_enum` value is `MMDB_FLOAT` and their
`mmdb_type_union` member is called `_float`.

#### 16-bit unsigned integer (uint16s)
`mmdb_uint16_t`  
`MMDB_UINT16`  
`_uint16`  

Uint16s represents 16-bit unsigned integers ranging from 0 to 2^16-1.
Their type is `mmdb_uint16_t`, their `mmdb_type_enum` value is `MMDB_UINT16` and their
`mmdb_type_union` member is called `_uint16`.

#### 32-bit unsigned integer (uint32s)
`mmdb_uint32_t`  
`MMDB_UINT32`  
`_uint32`  

Uint32s represent 32-bit unsigned integers ranging from 0 to 2^32-1.
Their type is `mmdb_uint32_t`, their `mmdb_type_enum` value is `MMDB_UINT32` and their
`mmdb_type_union` member is called `_uint32`.

#### 32-bit signed integer (int32s)
`mmdb_int32_t`  
`MMDB_INT32`  
`_int32`  

Int32s represent 32-bit two's complement signed integers ranging from -2^31 to 2^31-1.
Their type is `mmdb_int32_t`, their `mmdb_type_enum` value is `MMDB_INT32` and their
`mmdb_type_union` member is called `_int32`.

#### 64-bit unsigned integer (uint64s)
`mmdb_uint64_t`  
`MMDB_UINT64`  
`_uint64`  

Uint64s represent 64-bit unsigned integers ranging from 0 to 2^64-1.
Their type is `mmdb_uint64_t`, their `mmdb_type_enum` value is `MMDB_UINT64` and their
`mmdb_type_union` member is called `_uint64`.

As portable C99 code cannot guarantee that such a long type is available, the data is
represented in an array with 8 `uint8_t` elements that can be reached through the `data`
member of the resulting structure.  This may change in the future.

#### 128-bit unsigned integer (uint128s)
`mmdb_uint128_t`  
`MMDB_UINT128`  
`_uint128`  

Uint128s represent 128-bit unsigned integers ranging from 0 to 2^128-1.
Their type is `mmdb_uint128_t`, their `mmdb_type_enum` value is `MMDB_UINT128` and their
`mmdb_type_union` member is called `_uint128`.

As portable C99 code cannot guarantee that such a long type is available, the data is
represented in an array with 16 `uint8_t` elements that can be reached through the `data`
member of the resulting structure. This may change in the future.

#### UTF-8 character strings (strings)
`mmdb_string_t`  
`MMDB_STRING`  
`_string`  

Strings represent a series of UTF-8 characters as the individual bytes of the representation.
Their type is `mmdb_string_t`, their `mmdb_type_enum` value is `MMDB_STRING` and their
`mmdb_type_union` member is called `_string`.

Their length in bytes (excluding the final '\0') is represented by the `length` member of
the structure and the '\0' terminated array with the specific string can be found on the
`data` member.

Keep in mind that although the final '\0' is provided for simplicity, the MaxMind DB format
specficification doesn't guarantee that strings will not contain NULL characters in the
middle (represented as '\0' in UTF-8), because of this, using the length when handling strings
is recommended unless you are certain the data doesn't contain NULL characters.

#### Binary strings (bytes)
`mmdb_bytes_t`  
`MMDB_BYTES`  
`_bytes`  

Bytes represent arbitrary binary data.
Their type is `mmdb_bytes_t`, their `mmdb_type_enum` value is `MMDB_BYTES` and their
`mmdb_type_union` member is called `_bytes`.

Their length in bytes is represented by the `length` member of the structure and the
specific data is contained as an array of `uint8_t` elements by the `data` member.

#### Object arrays (arrays)
`mmdb_array_t`  
`MMDB_ARRAY`  
`_array`  

Arrays represent a zero-indexed ordered collection of objects.
Their type is `mmdb_array_t`, their `mmdb_type_enum` value is `MMDB_ARRAY` and their
`mmdb_type_union` member is called `_array`.

The number of objects they contain is specified by the `length` member of the structure
and the specific objects are contained as an array of `mmbd_type_t` elements by the
`entries` member.

This data structure may change in the future.

#### Object maps (maps)
`mmdb_map_t`  
`MMDB_MAP`  
`_map`  

Maps represent a maping of strings to objects.
Their type is `mmdb_map_t`, their `mmdb_type_enum` value is `MMDB_MAP` and their
`mmdb_type_union` member is called `_map`.

The number of entires they contain is specified by the `length` member of the structure,
the keys are contained as an array of `mmdb_string_t` elements by the `keys` member and
the specific valies  are contained as an array of `mmbd_type_t` elements by the
`values` member.

This data structure may change in the future.

### Accessing arrays
`mmdb_type_t * mmdb_array_get(const mmdb_type_t * array, mmdb_length_t pos)`  

Array elements can be accessed using `mmdb_array_get` the first parameter is the array
itself and the second the position at which the desired object is.

This function will return a pointer to the object in the array if the object is found or
a `NULL` pointer otherwise or if a problem happens. Since the returned object is a reference
to the one in the array, it shouldn't be freed by `mmdb_type_free` and will be freed
if the array containing the object is freed.

### Accessing maps
`mmdb_type_t * mmdb_map_get(const mmdb_type_t * map, const char * key, size_t len)`  
`mmdb_type_t * mmdb_map_gets(const mmdb_type_t * map, const char * key)`  

Map elements can be accessed using either `mmdb_map_get` or `mmdb_map_gets`. The first
parameter is the map itself and the second one the key to extract from the map.
`mmdb_map_gets` expects the key to be terminated by a '\0' (i.e. be a c-style string)
whilst `mmdb_map_get` requires the string length as its third parameter.

These functions will return a pointer to the object in the map if found or a `NULL`
pointer otherwise or if a problem happens. Since the returned object is a reference
to the one in the map, it shouldn't be freed by `mmdb_type_free` and will be freed
if the map containing the object is freed.

Internally `mmdb_map_gets` uses `mmdb_map_get`.

The current implementation is rather slow as it first compares the string lengths and
then their data with each key until it finds a match. This is done to keep the memory
footprint small. In the future other data structures may be used instead.

### Displaying objects
`void mmdb_print(const mmdb_type_t * lr)`

The `mmdb_print` function allows displaying objects on standard output. It takes as input
the object to be printed and will output it in a JSON-like format.

### Opening a database
`mmdb_t * mmdb_open(const char * path)`  

To open a database use `mmdb_open`. This function will open the file at path, extract the
metadata needed for the operation of the system and return a pointer to an `mmdb_t` object
that can be used in subsequent calls. If any problem is encountered, it will instead return
a NULL pointer. The resulting object must be freed with a call to `mmdb_close` if it won't be
used anymore.

Please note that the `mmdb_t` structure is kept opaque on purpose as it shouldn't be tampered
with outside of mmdb.

### Setting the maximum parsing depth
`MMDB_MAX_DEPTH`  
`void mmdb_set_max_depth(mmdb_t * db, uint32_t max_depth)`  

The MaxMind DB format theorically allows an array or map to contain a pointer to themselves.
This would result in an infinite loop that would eventually exhaust the stack or the memory
of the system. In order to prevent this, this library sets a maximum parsing depth when
reading data from the database, any reads deeper than this will fail.

By default this depth is 16 but can been changed by setting the value of the macro
`MMDB_MAX_DEPTH` at compile time.

Alternatively you can change the depth at runtime by calling `mmdb_set_max_depth` for the
target opened DB file.

### Obtaining database metadata
`mmdb_type_t * mmdb_read_metadata(const mmdb_t * db)`

To read the database metadata call `mmdb_read_metadata` with a pointer to the target
`mmdb_t` database.

This function will return a pointer to a `mmdb_type_t` map if sucessful or a `NULL`
pointer if a problem happens. This object must be freed with `mmdb_type_free` when it
won't be used anymore.

### Looking up ip addresses
`mmdb_type_t * mmdb_lookup4(const mmdb_t * db, const uint8_t ip[4])`  
`mmdb_type_t * mmdb_lookup6(const mmdb_t * db, const uint8_t ip[16])`  

To look up ip addresses call `mmdb_lookup4` or `mmdb_lookup6` passing a pointer
to the target `mmdb_t` database as first argument and a pointer to the binary
representation of the IP as the second one. IP addresses must be in network order
(that is big endian order) when looked up and be exaclty 4 octets long for `mmdb_lookup4`
and 16 for `mmdb_lookup6`.

`mmdb_lookup4` is used to look up IPv4 addresses whilst `mmdb_lookup6` is used to look
up IPv6 addresses (or any IPv4 mapped in IPv6 address). IPv4 lookups on IPv6 databases
will succeed as the function will automatically map the IP as specified on the MaxMind DB
specification, on the other hand IPv6 lookups in IPv4 databases will fail.

These functions will return a pointer to a `mmdb_type_t` object if sucessful or a `NULL`
pointer if a problem happens. This object must be freed with `mmdb_type_free` when it
won't be used anymore.

### Freeing unused results
`void mmdb_type_free(mmdb_type_t * data)`

The function `mmdb_type_free` should be used to clean up the results of `mmdb_read_metadata`,
`mmdb_lookup4` and `mmdb_lookup6`. This function will recursively free all the objects contained
by this object.

Keep in mind that any pointers to objects contained by the resulting object will be invalid
once you do this. This includes any objects extracted from maps or arrays. Thus, this
function shoudln't be called until you can guarantee that the object and any objects it contains
won't be used anymore.

When using this library to extract specific data, ensure you make a copy of the data you are
going to return BEFORE calling this method.

### Closing a database
`void mmdb_close(mmdb_t * db)`

The function `mmdb_close` will close the database and free all resources associated with it (other
than any objects returned by metadata or ip look ups). Any pointers to the specific `mmdb_t` object
will become invalid once this happens.

You should call it when you are done using the database or to refresh the database after an update.

### Database updates
MMDB will likely fail in unpredictable ways if a database file is updated while the database is open.
This is caused by MMDB caching the location of the metadata and data sections and some of the metadata
when calling `mmdb_open`.

If database updates are needed the connections should first be closed with `mmdb_close` and new ones
opened with `mmdb_open`. Keep in mind that this will make any old pointers to the old `mmdb_t` objects
invalid.

## Example
A simple example program is provided in the example.c file. Once compiled with mmdb it
can be used to extract data from a MaxMind DB file. To execute it just pass the file
as first argument followed by the ip addresses to be looked up as individual arguments.

The program will return a JSON-like structure with the results of each lookup or the
relevant errors if needed.

## Security considerations
Defensive programming techniques have been used whilst developing this tool, including
clear failure paths able to clean up after themselves and avoiding complex use of pointer
logic. Despite that this liibrary hasn't been thoroughly tested so there is a risk that
security problem may be present in it. The author isn't responsible in any case of any
such issues.

Additionally, some other issues are already known and unavoidable given the way in which
this library is implemented, these are documented in the following sections.

### Stack overflows for excessive parsing depth
The default of 16 is safe but users may set a depth of up to 2^32-1. This will result in
a stack overflow with some DB payloads, specially any containing a recursive structure, i.e.
a map or array pointing to itself.

### Exponential growth attacks
This way in which the DB format is specified allows for exponential growth attacks, that is,
an element may be used twice by an array that will then be used twice by an array, etc. Each
new array will, in this way, duplicate the size of the resulting object since objects are
always copied when parsed. A similar problem can also happen with maps.

Limiting the parsing depth can reduce the risk of this issue happening in some cases but since
objects can have arbitrary lengths will not nullify it.

This problem could be solved by using an object cache and read only objects with reference
counting instead of reading new copies from the database each time. This is, for now,
outside of the scope of the project though due to the complexity it would entail.

### Thread race conditions
The library uses internally fseek and fread in order to keep portability high. This means that
you must ensure that any calls to any APIs taking an mmdb_t structure as input must be
serialized using a mutex.

If you want to use the APIs in parallel consider using mmdb_open once per thread. This will 
cost you an additional open file descriptor per thread but address the concurrency problem.
