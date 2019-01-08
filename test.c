#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "kref_alloc.h"
#include "common.h"
#include "crypher.h"
#include "cryptfs.h"
#include "key_file.h"


int main()
{
    int rc = 0;
    struct cryptfs *cfs;
    char *key_filename = "/home/stelhs/kravchenko/CryptFS/key";
    char *folder = "/home/stelhs/kravchenko/CryptFS/crypted_fs";

    struct aes256xts *encoder, *decoder;
    struct buf *tweak1, *tweak2, *src, *encoded, *decoded;
 /*   char *enc;
    struct buf *key = buf_strdub("bla bla bla");

    enc = encrypt_path("/22", key, folder);
    printf("enc = %s\n", enc);*/

//    rc = cryptfs_generate_key_file("bla", key_filename);
    //printf("cryptfs_generate_key_file return %d\n", rc);

    cfs = cryptfs_create("/home/stelhs/kravchenko/CryptFS/crypted_fs",
                         key_filename);
    if (!cfs)
        print_e("cryptfs_create error\n");

    rc = cryptfs_mount(cfs, "/home/stelhs/kravchenko/CryptFS/uncrypted_fs", "bla");
    if (rc) {
        print_e("cryptfs_mount error: %d\n", rc);
    }

    cryptfs_loop(cfs);

/*    tweak1 = bufz_alloc(16);
    tweak2 = bufz_alloc(16);
    encoder = crypher_aes256xts_create(cfs->key_file->data_key, tweak1, 1);
    decoder = crypher_aes256xts_create(cfs->key_file->data_key, tweak2, 0);

    src = bufz_alloc(64);
    strcpy(src->data, "bla bla bla");

    buf_dump(src, "src");
    buf_dump(encoded, "decoded new");

    encoded = crypher_aes256xts_encrypt(encoder, src, 5);
    buf_dump(encoded, "encoded");

    decoded = crypher_aes256xts_decrypt(decoder, encoded, 5);
    buf_dump(decoded, "decoded");
*/
    return 0;
}

