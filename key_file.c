#include "common.h"
#include "crypher.h"
#include "cryptfs.h"
#include "key_file.h"

#define KEY_FILE_IV_LEN 12

static char key_file_iv[KEY_FILE_IV_LEN] = "123456789012";

static void key_file_destructor(void *mem)
{
    struct key_file *key_file = (struct key_file *)mem;
    buf_deref(&key_file->data_key);
    buf_deref(&key_file->header_iv);
}

struct key_file_uncrypt_format {
    u8 data_key[DATA_FILE_KEY_LEN];
    u8 header_iv[HEADER_FILE_IV_LEN];
};

int key_file_load(char *filename, struct buf *key,
                  struct key_file **new_key_file)
{
    struct buf *file_data, *tag;
    struct buf *encrypt_file_data;
    struct buf *uncrypt_buf;
    struct key_file *key_file;
    struct buf *iv_buf;
    struct key_file_uncrypt_format *uncrypt_format;
    int rc = -1;

    file_data = file_get_contents(filename);
    if (!file_data) {
        print_e("Can't open file %s\n", filename);
        goto out;
    }

    tag = buf_cpy(file_data->data, HEADER_FILE_IV_LEN);
    if (!tag) {
        print_e("Can't got TAG from file %s\n", filename);
        goto out;
    }

    encrypt_file_data = buf_cpy(file_data->data + HEADER_FILE_IV_LEN,
                                    file_data->len - HEADER_FILE_IV_LEN);
    if (!encrypt_file_data) {
        print_e("Can't got Key data from file %s\n", filename);
        goto out;
    }


    key_file = kzref_alloc(sizeof *key_file, key_file_destructor);
    if (!key_file) {
        print_e("Can't alloc for key_file struct\n");
        goto out;
    }

    iv_buf = buf_cpy(key_file_iv, KEY_FILE_IV_LEN);
    if (!iv_buf)
        goto out;

    rc = crypher_aes256gcm_decrypt(encrypt_file_data, &uncrypt_buf,
                                   tag, iv_buf, key);
    if (rc) {
        print_e("Can't decrypt key file data\n");
        goto out;
    }

    uncrypt_format = (struct key_file_uncrypt_format *)uncrypt_buf->data;

    key_file->data_key = buf_cpy(uncrypt_format->data_key,
                                 sizeof uncrypt_format->data_key);

    key_file->header_iv = buf_cpy(uncrypt_format->header_iv,
                                  sizeof uncrypt_format->header_iv);

    *new_key_file = kmem_ref(key_file);
    rc = 0;
out:
    kmem_deref(&key_file);
    buf_deref(&file_data);
    buf_deref(&tag);
    buf_deref(&encrypt_file_data);
    buf_deref(&uncrypt_buf);
    buf_deref(&iv_buf);
    return rc;
}

int key_file_save(struct key_file *key_file,
                  char *filename, struct buf *key)
{
    struct buf *iv_buf;
    struct buf *encrypt_file_data, *tag;
    struct buf *uncrypt_buf, *file_data;
    struct key_file_uncrypt_format *uncrypt_format;
    int rc = -1;

    uncrypt_buf = buf_alloc(sizeof (struct key_file_uncrypt_format));
    if (!uncrypt_buf)
        goto out;
    uncrypt_format = (struct key_file_uncrypt_format *)
                            uncrypt_buf->data;
    memcpy(uncrypt_format->data_key, key_file->data_key->data,
           sizeof uncrypt_format->data_key);
    memcpy(uncrypt_format->header_iv, key_file->header_iv->data,
           sizeof uncrypt_format->header_iv);
    printf("2\n");

    iv_buf = buf_cpy(key_file_iv, KEY_FILE_IV_LEN);
    if (!iv_buf)
        goto out;

    rc = crypher_aes256gcm_encrypt(uncrypt_buf,
                                   &encrypt_file_data, &tag,
                                   iv_buf, key);
    if (rc) {
        print_e("Can't encrypt key file data\n");
        goto out;
    }

    file_data = buf_concatenate(tag, encrypt_file_data);
    if (!file_data) {
        print_e("Can't alloc for file_data\n");
        goto out;
    }

    rc = file_put_contents(filename, file_data);
    if (rc) {
        print_e("Can't write key file: %s\n", filename);
        goto out;
    }

    rc = 0;
out:
    buf_deref(&encrypt_file_data);
    buf_deref(&iv_buf);
    buf_deref(&tag);
    buf_deref(&uncrypt_buf);
    buf_deref(&file_data);
    return rc;
}
