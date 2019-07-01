#include <stddef.h>

#define TRUE  1
#define FALSE 0

typedef unsigned char u8;
typedef unsigned int u32;
typedef u8 BOOL;
typedef u8 byte;
typedef unsigned int uint;
typedef unsigned long ulong;

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

