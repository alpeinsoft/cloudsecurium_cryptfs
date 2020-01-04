#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>

#define TRUE  1
#define FALSE 0

typedef unsigned char u8;
typedef unsigned int u32;

#ifdef _WIN32
    #ifndef __cplusplus
        #include <stdbool.h>
    #endif
#else
    #ifndef __cplusplus
        typedef u8 bool;
    #endif
#endif
typedef u8 byte;
typedef unsigned int uint;
typedef unsigned long ulong;

#ifdef _WIN32
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    typedef long off_t;
    #ifndef mode_t
        typedef int mode_t;
    #endif
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) (type *)( (u8 *)(ptr) - offsetof(type,member) )

#endif
