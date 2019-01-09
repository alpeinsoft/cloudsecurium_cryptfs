#ifndef KEY_FILE_H_
#define KEY_FILE_H_

#include "common.h"

struct key_file {
    struct buf *data_key;
};

int key_file_load(char *filename, struct buf *key,
                  struct key_file **new_key_file);

int key_file_save(struct key_file *key_file,
                  char *filename, struct buf *key);

struct key_file *key_file_container_create();

#endif /* KEY_FILE_H_ */
