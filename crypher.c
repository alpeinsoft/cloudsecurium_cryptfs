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
                              struct buf **dst, struct buf **tag,
                              struct buf *iv, struct buf *key)
{
    EVP_CIPHER_CTX *c;
    int len, ciphertext_len;
    int rc = -1;
    int evp_rc;

    *dst = buf_alloc(src->len);
    if (!*dst)
        goto out;

    *tag = buf_alloc(16);
    if (!*tag)
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

    evp_rc = EVP_EncryptUpdate(c, (*dst)->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't encrypt\n");
        EVP_print_errors();
        goto out;
    }
    ciphertext_len = len;
    printf("ciphertext_len = %d\n", ciphertext_len);

    evp_rc = EVP_EncryptFinal_ex(c, (*dst)->data + len, &len);
    if (evp_rc != 1) {
        print_e("can't finished encrypt\n");
        EVP_print_errors();
        goto out;
    }
    ciphertext_len += len;
    printf("ciphertext_len = %d\n", ciphertext_len);
    (*dst)->len = ciphertext_len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, (*tag)->data);
    if (evp_rc != 1) {
        print_e("can't get TAG\n");
        EVP_print_errors();
        goto out;
    }
    EVP_CIPHER_CTX_free(c);
    rc = 0;
    buf_ref(*dst);
    buf_ref(*tag);
out:
    buf_deref(*dst);
    buf_deref(*tag);
    return rc;
}


int crypher_aes256gcm_decrypt(struct buf *src, struct buf **dst,
                              struct buf *tag, struct buf *iv,
                              struct buf *key)
{
    EVP_CIPHER_CTX *c;
    int len, dst_len;
    int rc = -1;
    int evp_rc;

    *dst = buf_alloc(src->len);
    if (!*dst)
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

    evp_rc = EVP_DecryptUpdate(c, (*dst)->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't decrypt\n");
        EVP_print_errors();
        goto out;
    }
    dst_len = len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag->data);
    if (evp_rc != 1) {
        print_e("Can't set TAG\n");
        EVP_print_errors();
        goto out;
    }

    evp_rc = EVP_DecryptFinal_ex(c, (*dst)->data + len, &len);
    if (evp_rc != 1) {
        rc = -2;
        print_e("can't finalize decrypt\n");
        EVP_print_errors();
        goto out;
    }
    dst_len += len;
    (*dst)->len = dst_len;

    EVP_CIPHER_CTX_free(c);
    rc = 0;
    buf_ref(*dst);
out:
    buf_deref(*dst);
    return rc;
}

struct buf *md5sum(struct buf *src)
{
    MD5_CTX md5;
    uint len;
    u8 *p;
    struct buf *dst = buf_alloc(16);
    if (!dst) {
        perror("Can't alloc for md5summ\n");
        return NULL;
    }

    p = src->data;
    len = src->len;
    MD5_Init(&md5);
    while (len > 0) {
        if (len > 512)
            MD5_Update(&md5, p, 512);
        else
            MD5_Update(&md5, p, len);

        len -= 512;
        p += 512;
    }
    MD5_Final(dst->data, &md5);
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

