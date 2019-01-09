#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <math.h>
#include "common.h"
#include "buf.h"
#include "base32.h"
#include "crypher.h"

struct aes256xts {
    EVP_CIPHER_CTX *c;
    struct buf *tweak;
    u32 block_start;
};


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
        goto err;

    tag = buf_alloc(AES256GCM_TAG_LEN);
    if (!tag)
        goto err;

    c = EVP_CIPHER_CTX_new();
    if (!c) {
        print_e("can't create CIPHER_CTX\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (evp_rc != 1) {
        print_e("can't init encrypt EVP_aes_256_gcm\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_EncryptInit_ex(c, NULL, NULL, key->data, iv->data);
    if (evp_rc != 1) {
        print_e("can't set key and IV\n");
        EVP_print_errors();
        goto err;
    }

    ciphertext_len = 0, len = 0;

    evp_rc = EVP_EncryptUpdate(c, dst->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't encrypt\n");
        EVP_print_errors();
        goto err;
    }
    ciphertext_len = len;

    evp_rc = EVP_EncryptFinal_ex(c, dst->data + len, &len);
    if (evp_rc != 1) {
        print_e("can't finished encrypt\n");
        EVP_print_errors();
        goto err;
    }
    ciphertext_len += len;
    dst->len = ciphertext_len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG,
                                 AES256GCM_TAG_LEN, tag->data);
    if (evp_rc != 1) {
        print_e("can't get TAG\n");
        EVP_print_errors();
        goto err;
    }
    EVP_CIPHER_CTX_free(c);
    rc = 0;
    *new_dst = buf_ref(dst);
    *new_tag = buf_ref(tag);
err:
    buf_deref(&dst);
    buf_deref(&tag);
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
        goto err;

    c = EVP_CIPHER_CTX_new();
    if (!c) {
        print_e("can't create CIPHER_CTX\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (evp_rc != 1) {
        print_e("can't init decrypt EVP_aes_256_gcm\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_DecryptInit_ex(c, NULL, NULL, key->data, iv->data);
    if (evp_rc != 1) {
        print_e("can't set key and IV\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_DecryptUpdate(c, dst->data, &len, src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't decrypt\n");
        EVP_print_errors();
        goto err;
    }
    dst_len = len;

    evp_rc = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG,
                                 AES256GCM_TAG_LEN, tag->data);
    if (evp_rc != 1) {
        print_e("Can't set TAG\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_DecryptFinal_ex(c, dst->data + len, &len);
    if (evp_rc != 1) {
        rc = -2;
        print_e("can't finalize decrypt\n");
        EVP_print_errors();
        goto err;
    }
    dst_len += len;
    dst->len = dst_len;

    EVP_CIPHER_CTX_free(c);
    rc = 0;
    *new_dst = buf_ref(dst);
err:
    buf_deref(&dst);
    return rc;
}

static void aes256xts_destructor(void *mem)
{
    struct aes256xts *coder = (struct aes256xts *)mem;
    EVP_CIPHER_CTX_free(coder->c);
    kmem_deref(&coder->tweak);
}

struct aes256xts *crypher_aes256xts_create(struct buf *key,
                                           struct buf *tweak,
                                           bool enc_dec)
{
    struct aes256xts *coder;
    EVP_CIPHER_CTX *c;
    int evp_rc;
    u32 *block_num;

    coder = kzref_alloc(sizeof *coder, aes256xts_destructor);
    if (!coder) {
        print_e("Can't alloc aes256xts encoder\n");
        goto err;
    }

    c = EVP_CIPHER_CTX_new();
    if (!c) {
        print_e("can't create CIPHER_CTX\n");
        EVP_print_errors();
        goto err;
    }

    coder->c = c;
    coder->tweak = tweak;
    block_num = (u32 *)(coder->tweak->data + 12);
    coder->block_start = *block_num;

    if (enc_dec)
        evp_rc = EVP_EncryptInit_ex(c, EVP_aes_256_xts(), NULL, key->data, NULL);
    else
        evp_rc = EVP_DecryptInit_ex(c, EVP_aes_256_xts(), NULL, key->data, NULL);
    if (evp_rc != 1) {
        print_e("can't init (en/de)crypt EVP_aes_256_xts\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_CIPHER_CTX_set_padding(c, 0);
    if (evp_rc != 1) {
        print_e("can't set padding\n");
        EVP_print_errors();
        goto err;
    }

    kmem_ref(coder);
err:
    kmem_deref(&coder);
    return coder;
}

struct buf *crypher_aes256xts_encrypt(struct aes256xts *encoder,
                                      struct buf *src,
                                      uint block_number)
{
    struct buf *dst = NULL;
    int evp_rc;
    u32 *block_num;
    uint len;

    dst = buf_alloc(src->len);
    if (!dst) {
        print_e("can't alloc for destination buffer\n");
        goto err;
    }

    block_num = (u32 *)(encoder->tweak->data + 12);
    *block_num = encoder->block_start + block_number;
    evp_rc = EVP_EncryptInit_ex(encoder->c, NULL, NULL,
                                NULL, encoder->tweak->data);
    if (evp_rc != 1) {
        print_e("can't set tweak\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_EncryptUpdate(encoder->c, dst->data, &dst->len,
                               src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't encrypt\n");
        EVP_print_errors();
        goto err;
    }
    buf_ref(dst);
err:
    buf_deref(&dst);
    return dst;
}


struct buf *crypher_aes256xts_decrypt(struct aes256xts *decoder,
                                      struct buf *src,
                                      uint block_number)
{
    struct buf *dst = NULL;
    int evp_rc;
    u32 *block_num;
    uint len;

    dst = buf_alloc(src->len);
    if (!dst) {
        print_e("can't alloc for destination buffer\n");
        goto err;
    }

    block_num = (u32 *)(decoder->tweak->data + 12);
    *block_num = decoder->block_start + block_number;
    evp_rc = EVP_DecryptInit_ex(decoder->c, NULL, NULL, NULL,
                                decoder->tweak->data);
    if (evp_rc != 1) {
        print_e("can't set tweak\n");
        EVP_print_errors();
        goto err;
    }

    evp_rc = EVP_DecryptUpdate(decoder->c, dst->data, &dst->len,
                               src->data, src->len);
    if (evp_rc != 1) {
        print_e("can't decrypt\n");
        EVP_print_errors();
        goto err;
    }
    buf_ref(dst);
err:
    buf_deref(&dst);
    return dst;
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


struct buf *base64_encode(struct buf *in)
{
    BIO *buff, *b64f;
    struct buf *out = NULL;
    int rc;
    uint len;
    char *bio_out;

    b64f = BIO_new(BIO_f_base64());
    if (!b64f)
        goto err;

    buff = BIO_new(BIO_s_mem());
    if (!buff)
        goto err;

    buff = BIO_push(b64f, buff);
    if (!buff)
        goto err;

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    rc = BIO_write(buff, in->data, in->len);
    if (!rc) {
        print_e("Can't BIO_write\n");
        goto err;
    }
    BIO_flush(buff);

    len = BIO_get_mem_data(buff, &bio_out);

    out = buf_alloc(len + 1);
    if (!out) {
        print_e("Can't alloc out buffer\n");
        goto err;
    }
    memcpy(out->data, bio_out, len);
    out->data[len] = '\0';

    buf_ref(out);
err:
    BIO_free_all(buff);
    buf_deref(&out);
    return out;
}

struct buf *base64_decode(struct buf *in)
{
    BIO *buff, *b64f;
    struct buf *out = NULL;

    b64f = BIO_new(BIO_f_base64());
    if (!b64f)
        goto err;

    buff = BIO_new_mem_buf(in->data, in->len);
    if (!buff)
        goto err;

    buff = BIO_push(b64f, buff);
    out = buf_alloc(in->len + 1);
    if (!out) {
        print_e("Can't alloc out buffer\n");
        goto err;
    }

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    out->len = BIO_read(buff, out->data, in->len);
    if (!out->len) {
        print_e("Can't alloc out buffer\n");
        goto err;
    }
    out->data[out->len] = '\0';

    buf_ref(out);
err:
    BIO_free_all(buff);
    buf_deref(&out);
    return out;
}

struct buf *base32_encode_buf(struct buf *in)
{
    struct buf *out;
    out = bufz_alloc(BASE32_LEN(in->len) + 1);
    if (!out) {
        print_e("Can't alloc for base32_encode_buf\n");
        return NULL;
    }

    base32_encode(in->data, in->len, out->data);
    return out;
}

struct buf *base32_decode_buf(struct buf *in)
{
    struct buf *out;
    out = buf_alloc(in->len);
    if (!out) {
        print_e("Can't alloc for base32_decode_buf\n");
        return NULL;
    }

    out->len = base32_decode(in->data, out->data);
    return out;
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

static uint get_aligned_file_name_len(uint name_len)
{
    uint align = 5;
    return (name_len / align + 1) * align;
}

char *decrypt_file_name(char *name, struct buf *key)
{
    struct buf *name_buf;
    struct buf *hash;
    struct buf *decode_base32_name;
    struct buf *decrypted;
    uint len_aligned;
    int i;

    if (!name || !key) {
        print_e("incorrect args for decrypt_file_name\n");
        return NULL;
    }

    name_buf = buf_strdub(name);
    if (!name_buf) {
        print_e("Can't alloc name_buf\n");
        goto out;
    }

    decode_base32_name = base32_decode_buf(name_buf);
    if (!decode_base32_name) {
        print_e("Can't decode decode_base32_name\n");
        goto out;
    }

    len_aligned = decode_base32_name->len;

    decrypted = buf_alloc(len_aligned);
    if (!decrypted) {
        print_e("Can't alloc decrypted\n");
        goto out;
    }

    hash = md5sum(key, len_aligned);
    if (!hash) {
        print_e("Can't get md5 for file name\n");
        goto out;
    }

    /* XOR file name with hash2 */
    for (i = 0; i < decode_base32_name->len; i++)
        decrypted->data[i] = decode_base32_name->data[i] ^ hash->data[i];

    buf_ref(decrypted);
out:
    buf_deref(&name_buf);
    buf_deref(&hash);
    buf_deref(&decode_base32_name);
    buf_deref(&decrypted);
    return buf_to_str(decrypted);
}

struct buf *encrypt_file_name(char *name, struct buf *key)
{
    struct buf *hash;
    struct buf *encrypted;
    struct buf *base32_encrypted = NULL;
    struct buf *name_aligned;
    uint len = strlen(name);
    uint len_aligned = get_aligned_file_name_len(len);
    uint i;

    if (!name || !key) {
        print_e("incorrect args for encrypt_file_name\n");
        return NULL;
    }

    name_aligned = bufz_alloc(len_aligned);
    if (!name_aligned) {
        print_e("Can't alloc for name_aligned\n");
        goto err;
    }
    memcpy(name_aligned->data, name, len);

    hash = md5sum(key, len_aligned);
    if (!hash) {
        print_e("Can't get md5 for file name\n");
        goto err;
    }

    encrypted = bufz_alloc(len_aligned);
    if (!encrypted) {
        print_e("Can't alloc for encrypted file name\n");
        goto err;
    }

    /* XOR file name with hash2 */
    for (i = 0; i < len_aligned; i++)
        encrypted->data[i] = name_aligned->data[i] ^ hash->data[i];

    base32_encrypted = base32_encode_buf(encrypted);
    if (!base32_encrypted) {
        print_e("Can't got base32 for encrypted file name\n");
        goto err;
    }

    buf_ref(base32_encrypted);
err:
    buf_deref(&hash);
    buf_deref(&encrypted);
    buf_deref(&base32_encrypted);
    buf_deref(&name_aligned);
    return base32_encrypted;
}


char *encrypt_path(const char *uncrypt_path,
                   struct buf *key,
                   char *path_prefix)
{
    struct buf *crypt_path;
    struct list *parts;
    struct list *crypted_parts;
    uint crypt_path_len;
    struct le *le;
    char *p;
    uint path_prefix_len = strlen(path_prefix);

    parts = str_split(uncrypt_path, '/');
    if (!parts) {
        print_e("Can't split string: '%s'\n", uncrypt_path);
        goto err;
    }

    crypted_parts = list_create();
    if (!crypted_parts) {
        print_e("Can't alloc list crypted_parts\n");
        goto err;
    }

    crypt_path_len = path_prefix_len;
    LIST_FOREACH(parts, le) {
        struct buf *part = list_ledata(le);
        struct buf *crypted_part;
        crypted_part = encrypt_file_name(buf_to_str(part), key);
        if (!crypted_part) {
            print_e("Can't encrypt file name\n");
            goto err;
        }
        buf_list_append(crypted_parts, crypted_part);
        crypt_path_len += crypted_part->len + 1;
    }

    crypt_path = buf_alloc(crypt_path_len);
    if (!crypt_path) {
        print_e("can't alloc for crypt_path_len\n");
        goto err;
    }

    p = crypt_path->data;
    memcpy(p, path_prefix, path_prefix_len);
    p += path_prefix_len;
    if (path_prefix[path_prefix_len - 1] == '/')
        p--;

    LIST_FOREACH(crypted_parts, le) {
        struct buf *crypted_part = list_ledata(le);
        *p++ = '/';
        memcpy(p, crypted_part->data, crypted_part->len - 1);
        p += crypted_part->len - 1;
    }
    *p = 0;
    crypt_path->len = strlen(crypt_path->data);
    buf_ref(crypt_path);
err:
    buf_deref(&crypt_path);
    kmem_deref(&parts);
    kmem_deref(&crypted_parts);
    return buf_to_str(crypt_path);
}
