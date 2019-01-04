#include <stdlib.h>
#include <time.h>
#include "kref_alloc.h"
#include "common.h"

struct cryptfs {
    struct ubuf *key_file_data;

    struct ubuf *data_key;
    struct ubuf *header_key;
    struct ubuf *header_iv;

    char *folder;
    char *mount_point_path;
    struct fuse_chan *fc;
    struct fuse *fuse;
};


static void cryptfs_destructor(void *mem)
{
    struct cryptfs *cfs = (struct cryptfs *)mem;
    // TODO:
    kmem_deref(cfs->key_file_data);
    kmem_deref(cfs->data_key);
    kmem_deref(cfs->header_key);
    kmem_deref(cfs->header_iv);
    kmem_deref(cfs->folder);
    kmem_deref(cfs->mount_point_path);
}

struct cryptfs *cryptfs_create(char *crypted_folder, char *key_file_path)
{
    struct cryptfs *cfs;

    if (!dir_exist(crypted_folder)) {
        print_e("Encrypted path is not correct\n");
        return NULL;
    }

    if (!file_exist(key_file_path)) {
        print_e(".key file is not exist\n");
        return NULL;
    }

    cfs = kzref_alloc(sizeof(struct cryptfs), cryptfs_destructor);
    if (!cfs) {
        print_e("alloc cryptfs error\n");
        return NULL;
    }

    cfs->folder = kref_strdub(crypted_folder);
    if (!cfs->folder) {
        print_e("Can't copy crypted_folder\n");
        return NULL;
    }

    cfs->key_file_data = file_get_contents(key_file_path);
    if (!cfs->key_file_data) {
        print_e("Can't read key file\n");
        return NULL;
    }

    return cfs;
}

static int
uncrypt_key_file_data(struct ubuf *key_file_data, struct ubuf *keyfile_key,
                      struct ubuf **data_key, struct ubuf **header_iv)
{
    // TODO:

}

int cryptfs_mount(struct cryptfs *cfs, char *mount_point_path, char *password)
{
    struct ubuf *keyfile_key, *pass;
    int rc = -1;

    pass = buf_strdub(password);
    if (!pass)
        goto out;

    keyfile_key = md5sum(pass);
    if (!keyfile_key) {
        print_e("Can't got md5 for keyfile_key\n");
        return -1;
    }
    rc = uncrypt_key_file_data(cfs->key_file_data, keyfile_key,
                               &cfs->data_key, &cfs->header_iv);
    switch (rc) {
    case -3:
        print_e("incorrect password\n");
        goto out;

    case -4: // TODO:
        print_e("...\n");
        goto out;
    }

    cfs->header_key = md5sum(keyfile_key);
    if (!cfs->header_key) {
        print_e("Can't got md5 for header_key\n");
        goto out;
    }

    // TODO:

    rc = 0;
out:
    buf_deref(pass);
    kmem_deref(keyfile_key);
    return rc;
}

int cryptfs_ummount(struct cryptfs *cfs)
{
    return 0;
}

void cryptfs_loop(struct cryptfs *cfs)
{

}

int cryptfs_generate_key_file(char *password, char *key_file_path)
{
    struct ubuf *data_key, *header_iv, *data_iv;
    struct ubuf *keyfile_key, *encrypt_key_file_data, *tag;
    struct ubuf *pass;
    struct ubuf *key_file_uncrypt_buf, *key_file_data;
    struct key_file_uncrypt *key_file_uncrypt_data;
    int rc = -1;

    data_key = gen_rand_buf(64);
    if (!data_key) {
        print_e("Can't generate new data key\n");
        goto out;
    }

    header_iv = gen_rand_buf(12);
    if (!header_iv) {
        print_e("Can't generate new header IV\n");
        goto out;
    }

    key_file_uncrypt_buf = buf_alloc(sizeof (struct key_file_uncrypt));
    if (!key_file_uncrypt_buf)
        goto out;
    key_file_uncrypt_data = (struct key_file_uncrypt *)
                            key_file_uncrypt_buf->data;
    memcpy(key_file_uncrypt_data->data_key, data_key->data,
           sizeof key_file_uncrypt_data->data_key);
    memcpy(key_file_uncrypt_data->header_iv, header_iv->data,
           sizeof key_file_uncrypt_data->header_iv);

    pass = buf_strdub(password);
    if (!pass)
        goto out;

    keyfile_key = md5sum(pass);
    buf_deref(pass);
    if (!keyfile_key) {
        print_e("Can't got md5 for keyfile_key\n");
        goto out;
    }

    data_iv = bufz_alloc(12);
    if (!data_iv)
        goto out;
    rc = aes256gcm_encrypt(key_file_uncrypt_buf,
                           &encrypt_key_file_data, &tag,
                           data_iv, keyfile_key);
    if (rc) {
        print_e("Can't encrypt key file data\n");
        return -1;
    }

    key_file_data = buf_concatenate(tag, encrypt_key_file_data);
    if (!key_file_data) {
        print_e("Can't alloc for key_file_data\n");
        return -1;
    }

    rc = file_put_contents(key_file_path, key_file_data);
    if (rc) {
        print_e("Can't write key file: %s\n", key_file_path);
        return -1;
    }

    rc = 0;
out:
    buf_deref(data_key);
    buf_deref(header_iv);
    buf_deref(data_iv);
    buf_deref(keyfile_key);
    buf_deref(encrypt_key_file_data);
    buf_deref(tag);
    buf_deref(pass);
    buf_deref(key_file_data);
    buf_deref(key_file_uncrypt_buf);
    return rc;
}

