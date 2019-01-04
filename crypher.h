#include "common.h"

void crypher_init();
int crypher_aes256gcm_encrypt(struct buf *src,
	        	              struct buf **dst, struct buf **tag,
		                      struct buf *iv, struct buf *key);

int crypher_aes256gcm_decrypt(struct buf *src, struct buf **dst,
							  struct buf *tag, struct buf *iv,
							  struct buf *key);
struct buf *md5sum(struct buf *src, uint md5len);
struct buf *make_rand_buf(uint len);
