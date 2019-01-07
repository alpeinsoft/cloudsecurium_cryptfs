#include "common.h"

#define AES256GCM_TAG_LEN 12

struct aes256xts;
void crypher_init();
int crypher_aes256gcm_encrypt(struct buf *src,
	        	              struct buf **dst, struct buf **tag,
		                      struct buf *iv, struct buf *key);

int crypher_aes256gcm_decrypt(struct buf *src, struct buf **dst,
							  struct buf *tag, struct buf *iv,
							  struct buf *key);

struct aes256xts *crypher_aes256xts_create(struct buf *key,
                                           struct buf *tweak,
                                           bool enc_dec);

struct buf *crypher_aes256xts_encrypt(struct aes256xts *encoder,
                                      struct buf *src,
                                      uint block_number);

struct buf *crypher_aes256xts_decrypt(struct aes256xts *decoder,
                                      struct buf *src,
                                      uint block_number);

struct buf *md5sum(struct buf *src, uint md5len);
struct buf *make_rand_buf(uint len);
struct buf *encrypt_file_name(char *name, struct buf *key);
char *decrypt_file_name(char *name, struct buf *key);
char *encrypt_path(const char *uncrypt_path,
                   struct buf *key,
                   char *path_prefix);
struct buf *base64_encode(struct buf *in);
struct buf *base64_decode(struct buf *in);
