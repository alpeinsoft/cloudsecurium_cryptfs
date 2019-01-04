#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include "common.h"

void crypher_init()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

static void EVP_print_errors()
{
    unsigned long err;
    while(err = ERR_get_error()) {
        char *msg = ERR_error_string(err, NULL);
        print_e("%s\n", msg);
    }
}

int crypher_aes256gcm_encrypt(struct buf *src,
                              struct buf **new_dst, struct buf **new_tag,
                              struct buf *iv, struct buf *key)
{
    EVP_CIPHER_CTX *c;
    int len, ciphertext_len;
    struct buf *dst, *tag;
    int rc = -1;
    int evp_rc;

    dst = buf_alloc(src->len);
    if (!dst)
        goto out;

    tag = buf_alloc(12);
    if (!tag)
        goto out;

    c = EVP_CIPHER_CTX_new();
    if (!c) {
        print_e("can't create CIPHER_CTX\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (evp_rc != 1) {
        print_e("can't init encrypt EVP_aes_256_gcm\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_EncryptInit_ex(c, NULL, NULL, key->data, iv->data);
    if (evp_rc != 1) {
        print_e("can't set key and IV\n");
        EVP_print_errors();
        goto out;
    }

    ciphertext_len = 0, len = 0;

    evp_rc = EVP_EncryptUpdate(c, dst->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't encrypt\n");
        EVP_print_errors();
        goto out;
    }
    ciphertext_len = len;

    evp_rc = EVP_EncryptFinal_ex(c, dst->data + len, &len);
    if (evp_rc != 1) {
        print_e("can't finished encrypt\n");
        EVP_print_errors();
        goto out;
    }
    ciphertext_len += len;
    dst->len = ciphertext_len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 12, tag->data);
    if (evp_rc != 1) {
        print_e("can't get TAG\n");
        EVP_print_errors();
        goto out;
    }
    EVP_CIPHER_CTX_free(c);
    rc = 0;
    *new_dst = buf_ref(dst);
    *new_tag = buf_ref(tag);
out:
    buf_deref(dst);
    buf_deref(tag);
    return rc;
}


int crypher_aes256gcm_decrypt(struct buf *src, struct buf **new_dst,
                              struct buf *tag, struct buf *iv,
                              struct buf *key)
{
    EVP_CIPHER_CTX *c;
    int len, dst_len;
    int rc = -1;
    int evp_rc;
    struct buf *dst;

    dst = buf_alloc(src->len);
    if (!dst)
        goto out;

    c = EVP_CIPHER_CTX_new();
    if (!c) {
        print_e("can't create CIPHER_CTX\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (evp_rc != 1) {
        print_e("can't init decrypt EVP_aes_256_gcm\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_DecryptInit_ex(c, NULL, NULL, key->data, iv->data);
    if (evp_rc != 1) {
        print_e("can't set key and IV\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_DecryptUpdate(c, dst->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't decrypt\n");
        EVP_print_errors();
        goto out;
    }
    dst_len = len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 12, tag->data);
    if (evp_rc != 1) {
        print_e("Can't set TAG\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_DecryptFinal_ex(c, dst->data + len, &len);
    if (evp_rc != 1) {
        rc = -2;
        print_e("can't finalize decrypt\n");
        EVP_print_errors();
        goto out;
    }
    dst_len += len;
    dst->len = dst_len;

    EVP_CIPHER_CTX_free(c);
    rc = 0;
    *new_dst = buf_ref(dst);
out:
    buf_deref(dst);
    return rc;
}

struct buf *md5sum(struct buf *src_buf, uint md5len)
{
    MD5_CTX md5;
    int len;
    u8 *src;
    char md5buf[16];
    uint dst_cnt = 0;

    struct buf *dst = buf_alloc(md5len);
    if (!dst) {
        perror("Can't alloc for md5summ\n");
        return NULL;
    }

    src = src_buf->data;
    len = src_buf->len;
    while(dst_cnt < md5len) {
        uint part_len = ((md5len - dst_cnt) < sizeof md5buf) ?
                              md5len - dst_cnt : sizeof md5buf;
        MD5_Init(&md5);
        while (len > 0) {
            if (len > 512)
                MD5_Update(&md5, src, 512);
            else
                MD5_Update(&md5, src, len);
            len -= 512;
            src += 512;
        }
        MD5_Final(md5buf, &md5);
        memcpy(dst->data + dst_cnt, md5buf, part_len);
        dst_cnt += part_len;
        src = md5buf;
        len = sizeof md5buf;
    }
    return dst;
}

struct buf *make_rand_buf(uint len)
{
    static bool first = 1;
    struct buf *buf;
    uint i;

    if (first) {
        srand ((uint) time(NULL));
        first = 0;
    }

    buf = buf_alloc(len);
    if (!buf)
        return NULL;
    for (i = 0; i < len; i++)
        buf->data[i] = rand();
    return buf;
}

struct buf *encrypt_file_name(char *name, struct buf *key)
{

}

char *encrypt_path(char *uncrypt_path, struct buf *key)
{
    uint len = strlen(uncrypt_path);
    int i;
    char *p;
    uint slashes_cnt = 0;
    uint max_len = 0;
    uint len_cnt = 0;
    uint max_crypt_path_len;
    uint max_crypt_name;
    char *crypt_path, *name;
    struct buf *crypt_name;
    uint dest_cnt;
    uint name_cnt;

    /* calculate max part name and slashes numbers */
    for (i = 0; i < len; i++) {
        p = uncrypt_path + i;
        if (*p == '/') {
            slashes_cnt ++;
            len_cnt = 0;
            continue;
        }
        len_cnt ++;
        if (len_cnt > max_len)
            max_len = len_cnt;
    }
    /* calculate maximum crypt_path length and allocate it */
    max_crypt_name = ceil(max_len / 16);
    max_crypt_path_len = max_crypt_name * slashes_cnt;
    crypt_path = kzref_alloc(max_crypt_path_len, NULL);
    if (!crypt_path) {
        print_e("can't alloc for crypt_path\n");
        goto out;
    }
    name = kzref_alloc(max_crypt_name, NULL);
    if (!name) {
        print_e("can't alloc for name\n");
        goto out;
    }

    dest_cnt = 0;
    p = name;
    for (i = 0; i < len; i++) {
        dest_cnt ++;
        if (uncrypt_path[i] != '/') {
            *p = uncrypt_path[i];
            p++;
            continue;
        }

        *p = 0;
        crypt_path[dest_cnt - 1] = uncrypt_path[i];
        crypt_name = encrypt_file_name(name, key);
        if (!crypt_name) {
            print_e("can't crypt file name\n");
            goto out;
        }
        memcpy(crypt_path + dest_cnt, crypt_name->data, crypt_name->len);
        kmem_deref(crypt_name);
        dest_cnt += crypt_name->len;
        p = name;
    }

    kmem_ref(crypt_path);
out:
    kmem_deref(crypt_path);
    kmem_deref(name);
    buf_deref(crypt_name);
    return crypt_path;
}

