#include "kref.h"

void kref_init(struct kref *kref)
{
    kref->refcount = 1;
}

void kref_get(struct kref *kref)
{
    kref->refcount ++;
}

int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
    kref->refcount--;
    if (!kref->refcount) {
        release(kref);
        return 1;
    }
    return 0;
}

