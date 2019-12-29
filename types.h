#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>

#define TRUE  1
#define FALSE 0

typedef unsigned char u8;
typedef unsigned int u32;
#ifdef __unix__
#ifndef __cplusplus
typedef u8 bool;
#endif
#else
#ifndef __cplusplus
#include <stdbool.h>
#endif
#endif
typedef u8 byte;
typedef unsigned int uint;
typedef unsigned long ulong;

#ifdef __unix__
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        typeof( ((type *)0)->member ) *__mptr = (ptr);  \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#else
#define container_of(ptr, type, member) (type *)( (char *)(ptr) - offsetof(type,member) )
#endif

#endif
