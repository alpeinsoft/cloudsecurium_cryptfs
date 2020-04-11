#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
    #include <sys/types.h>
    #include <sys/xattr.h>
    #include <sys/file.h>
    #include <libgen.h>
    #include <dirent.h>
    #include <unistd.h>
#else
    #include "win_dirent.h"
#endif
#include <string.h>

#ifdef __APPLE__
    #include <osxfuse/fuse.h>
    #include <osxfuse/fuse/fuse_lowlevel.h>
    #include <sys/mount.h>
#else
    #include <fuse.h>
#endif
#include "kref_alloc.h"
#include "key_file.h"
#include "crypher.h"
#include "cryptfs.h"
#include "buf.h"
#include "types.h"
#include "cfs_syscall.h"

static void cryptfs_destructor(void *mem)
{
    struct cryptfs *cfs = (struct cryptfs *)mem;
    kmem_deref(&cfs->keys_file_name);
    kmem_deref(&cfs->key_file);
    kmem_deref(&cfs->header_key);
    buf_deref(&cfs->file_name_key);
    kmem_deref(&cfs->folder);
    kmem_deref(&cfs->mount_point_folder);
    kmem_deref(&cfs->opened_files);
}

struct opened_file {
    struct le le;
    int fd;
    char *file_path;
    char *encrypted_path;
    int flags;
    struct cryptfs *cfs;
    struct file_header_format *file_header;
    off_t fsize;
    struct aes256xts *encrypher;
    struct aes256xts *decrypher;
    struct fuse_file_info *fi;
};

void opened_file_destructor(void *mem)
{
    struct opened_file *of = (struct opened_file *)mem;
    cfs_close(of->fd);
    list_unlink(&of->le);
    kmem_deref(&of->file_path);
    kmem_deref(&of->encrypted_path);
    kmem_deref(&of->file_header);
    kmem_deref(&of->encrypher);
    kmem_deref(&of->decrypher);
}

static struct file_header_format *
read_file_header(char *filename, struct buf *key)
{
    struct buf *tag = NULL;
    struct buf *header_data_enc = NULL;
    struct buf *header_data = NULL;
    struct buf *iv = NULL;
    struct file_header_format *file_header = NULL;
    uint len;
    int rc;
    int fd;

    fd = cfs_open(filename, O_RDONLY);
    if (fd < 0) {
        print_e("can't open %s, fd = %d, errno = %d\n", filename, fd, errno);
        rc = -errno;
        goto out;
    }

    tag = buf_alloc(HEADER_FILE_TAG_LEN);
    if (!tag) {
        print_e("Can't alloc for header tag\n");
        goto out;
    }

    iv = buf_alloc(HEADER_FILE_IV_LEN);
    if (!iv) {
        print_e("Can't alloc for header IV\n");
        goto out;
    }

    header_data_enc = buf_alloc(sizeof (struct file_header_format));
    if (!header_data_enc) {
        print_e("Can't alloc for header data\n");
        goto out;
    }

    len = cfs_pread(fd, iv->data, iv->len, 0);
    if (len != iv->len) {
        print_e("Can't read iv, len = %d, iv->len = %d\n",
                len, tag->len);
        goto out;
    }

    len = cfs_pread(fd, tag->data, tag->len, iv->len);
    if (len != tag->len) {
        print_e("Can't read tag, len = %d, tag->len = %d\n",
                len, tag->len);
        goto out;
    }

    len = cfs_pread(fd, header_data_enc->data, header_data_enc->len, tag->len+iv->len);
    if (len != header_data_enc->len) {
        print_e("Can't read header data\n");
        goto out;
    }

    rc = crypher_aes256gcm_decrypt(header_data_enc,
                                   &header_data, tag,
                                   iv, key);
    if (rc) {
        print_e("Can't decrypt file header\n");
        goto out;
    }

    file_header = (struct file_header_format *)header_data->data;
    kmem_ref(header_data);
out:
    cfs_close(fd);
    kmem_deref(&tag);
    kmem_deref(&iv);
    kmem_deref(&header_data_enc);
    kmem_deref(&header_data);
    return file_header;
}


static int
write_file_header(int fd, struct file_header_format *file_header,
                  struct buf *key)
{
    struct buf *header_data_enc = NULL;
    struct buf *header_data = NULL;
    struct buf *tag = NULL, *iv = NULL;
    uint len;
    int rc = -1;

    iv = make_rand_buf(HEADER_FILE_IV_LEN);
    if (!iv) {
        print_e("Can't generate IV\n");
        goto out;
    }

    header_data = buf_cpy(file_header, sizeof *file_header);
    if (!header_data) {
        print_e("Can't alloc for header_data\n");
        goto out;
    }

    rc = crypher_aes256gcm_encrypt(header_data, &header_data_enc,
                                   &tag, iv, key);
    if (rc) {
        print_e("Can't encrypt header_data\n");
        goto out;
    }

    len = cfs_pwrite(fd, iv->data, iv->len, 0);
    if (len != iv->len) {
        print_e("Can't write IV\n");
        rc = -errno;
        goto out;
    }

    len = cfs_pwrite(fd, tag->data, tag->len, iv->len);
    if (len != tag->len) {
        print_e("Can't write tag\n");
        rc = -errno;
        goto out;
    }

    len = cfs_pwrite(fd, header_data_enc->data, header_data_enc->len, iv->len + tag->len);
    if (len != header_data_enc->len) {
        print_e("Can't write encrypted file header\n");
        rc = -errno;
        goto out;
    }

    rc = 0;
out:
    kmem_deref(&header_data_enc);
    kmem_deref(&header_data);
    kmem_deref(&tag);
    kmem_deref(&iv);
    return rc;
}

static int update_file_header(struct opened_file *of, uint new_size)
{
    int rc;

    of->file_header->fsize = new_size;
    rc = write_file_header(of->fd, of->file_header,
                           of->cfs->key_file->data_key);
    if (rc) {
        print_e("Can't write file header\n");
        return -1;
    }
    return 0;
}

static struct buf *load_data_block(struct opened_file *of,
                                   off_t block_num)
{
    struct buf *enc_block = NULL;
    struct buf *block = NULL;
    int len;
    off_t needed_offset, offset;


    enc_block = buf_alloc(DATA_FILE_BLOCK_LEN);
    if (!enc_block) {
        print_e("Can't alloc for encrypted data block\n");
        goto out;
    }

    block = buf_alloc(DATA_FILE_BLOCK_LEN);
    if (!block) {
        print_e("Can't alloc for uncrypted data block\n");
        goto out;
    }

    needed_offset = block_num * DATA_FILE_BLOCK_LEN + HEADER_FILE_LEN;
    len = cfs_pread(of->fd, enc_block->data, enc_block->len, needed_offset);

    if (len != enc_block->len) {
        print_e("Can't read data block, len = %d, enc_block->len = %d\n",
                len, enc_block->len);
        if (len < 0)
            print_e("Read error: %s\n", strerror(errno));
        goto out;
    }

    block = crypher_aes256xts_decrypt(of->decrypher, enc_block, block_num);
    if (!block) {
        print_e("Can't decrypt data block\n");
        goto out;
    }

    kmem_ref(block);
out:
    kmem_deref(&enc_block);
    kmem_deref(&block);
    return block;
}


static int save_data_block(struct opened_file *of, off_t block_num,
                           struct buf *block)
{
    struct buf *enc_block = NULL;
    uint len;
    int rc = -1;

    enc_block = crypher_aes256xts_encrypt(of->encrypher, block, block_num);
    if (!enc_block) {
        print_e("Can't encrypt data block\n");
        goto out;
    }

    len = cfs_pwrite(of->fd, enc_block->data, enc_block->len, block_num * DATA_FILE_BLOCK_LEN + HEADER_FILE_LEN);
    if (len != enc_block->len) {
        print_e("Can't write data block\n");
        goto out;
    }
    rc = 0;
out:
    kmem_deref(&enc_block);
    return rc;
}



static uint get_aligned_file_name_len(uint name_len)
{
    uint align = 5;
    return (name_len / align + 1) * align;
}

static char *decrypt_file_name(struct cryptfs *cfs,
                               char *enc_file_name)
{
    struct buf *enc_file_name_buf = NULL;
    struct buf *decode_base32_enc_fname = NULL;
    struct buf *enc_fname = NULL, *tag = NULL, *fname = NULL;
    struct buf *iv = NULL;
    struct buf *key = NULL;
    u8 *p;
    int rc;

    if (!enc_file_name || !cfs) {
        print_e("incorrect args for decrypt_file_name\n");
        return NULL;
    }
    iv = cfs->key_file->file_iv;
    key = cfs->file_name_key;

    enc_file_name_buf = buf_strdub(enc_file_name);
    if (!enc_file_name_buf) {
        print_e("Can't alloc enc_name_buf\n");
        goto out;
    }

    decode_base32_enc_fname = base32_decode_buf(enc_file_name_buf);
    if (!decode_base32_enc_fname) {
        print_e("Can't decode enc_fname_buf\n");
        goto out;
    }

    if (decode_base32_enc_fname->len < FILE_NAME_TAG_LEN) {
        print_e("Decrypted file name is short\n");
        goto out;
    }

    p = decode_base32_enc_fname->data;
    tag = buf_cpy(p, FILE_NAME_TAG_LEN);
    if (!tag) {
        print_e("Can't copy TAG\n");
        goto out;
    }
    p += FILE_NAME_TAG_LEN;

    enc_fname = buf_cpy(p, decode_base32_enc_fname->len -
                           FILE_NAME_TAG_LEN);
    if (!enc_fname) {
        print_e("Can't copy encrypthed file name\n");
        goto out;
    }

    rc = crypher_aes256gcm_decrypt(enc_fname, &fname, tag, iv, key);
    if (rc) {
        print_e("Can't decrypt file name\n");
        goto out;
    }

    buf_ref(fname);
out:
    buf_deref(&enc_file_name_buf);
    buf_deref(&decode_base32_enc_fname);
    buf_deref(&enc_fname);
    buf_deref(&tag);
    buf_deref(&fname);
    return buf_to_str(fname);
}

static struct buf *
encrypt_file_name(char *name, struct buf *key, struct buf *iv)
{
    struct buf *base32_enc_fname = NULL;
    struct buf *enc_fname_aligned;
    struct buf *name_buf, *name_enc_buf, *tag;
    uint flen = strlen(name);
    uint flen_aligned;
    uint full_len;
    uint aligned_full_len;
    uint i;
    int rc;

    if (!name || !key) {
        print_e("incorrect args for encrypt_file_name\n");
        return NULL;
    }

    full_len = FILE_NAME_TAG_LEN + flen;
    aligned_full_len = get_aligned_file_name_len(full_len);
    flen_aligned = flen + (aligned_full_len - full_len);

    name_buf = bufz_alloc(flen_aligned);
    if (!name_buf) {
        print_e("Can't alloc new aligned file name\n");
        goto err;
    }
    memcpy(name_buf->data, name, flen);

    rc = crypher_aes256gcm_encrypt(name_buf, &name_enc_buf, &tag, iv, key);
    if (rc) {
        print_e("Can't encrypt file name\n");
        goto err;
    }

    enc_fname_aligned = bufz_alloc(flen_aligned + FILE_NAME_TAG_LEN);
    if (!enc_fname_aligned) {
        print_e("Can't alloc for enc_fname_aligned\n");
        goto err;
    }
    memcpy(enc_fname_aligned->data, tag->data, tag->len);
    memcpy(enc_fname_aligned->data + tag->len,
           name_enc_buf->data, name_enc_buf->len);

    base32_enc_fname = base32_encode_buf(enc_fname_aligned);
    if (!base32_enc_fname) {
        print_e("Can't got base32 for encrypted file name\n");
        goto err;
    }

    buf_ref(base32_enc_fname);
err:
    buf_deref(&enc_fname_aligned);
    buf_deref(&base32_enc_fname);
    buf_deref(&name_buf);
    buf_deref(&name_enc_buf);
    buf_deref(&tag);
    return base32_enc_fname;
}


static char *encrypt_path(struct cryptfs *cfs,
                          const char *uncrypt_path,
                          const char *path_prefix)
{
    struct buf *crypt_path = NULL;
    struct list *parts = NULL;
    struct list *crypted_parts = NULL;
    uint crypt_path_len;
    struct le *le;
    char *p;
    struct buf *iv = cfs->key_file->file_iv;
    struct buf *key = cfs->file_name_key;
    uint path_prefix_len = strlen(path_prefix);
    char *result = NULL;

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
        crypted_part = encrypt_file_name(buf_to_str(part), key, iv);
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

    p = (char *)crypt_path->data;
    memcpy(p, path_prefix, path_prefix_len);
    p += path_prefix_len;
    if (path_prefix[path_prefix_len - 1] == '/'
#ifndef _WIN32
            )
#else
            || path_prefix[path_prefix_len - 1] == '\\')
#endif
        p--;

    LIST_FOREACH(crypted_parts, le) {
        struct buf *crypted_part = list_ledata(le);
#ifndef _WIN32
        *p++ = '/';
#else
        *p++ = '\\';
#endif
        memcpy(p, crypted_part->data, crypted_part->len - 1);
        p += crypted_part->len - 1;
    }

    *p = 0;
    crypt_path->len = strlen((const char *)crypt_path->data);
    buf_ref(crypt_path);
err:
    buf_deref(&crypt_path);
    kmem_deref(&parts);
    kmem_deref(&crypted_parts);
    return buf_to_str(crypt_path);
}



static int fs_flush(const char *path, struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    struct cryptfs *cfs = of->cfs;
    struct le *le;
    int rc = 0;

    print_d("call fs_flush %s\n", path);

    if (of->fsize != of->file_header->fsize) {
        print_d("call update_file_header, fsize = %jd\n", of->fsize);
        rc = update_file_header(of, of->fsize);
        if (rc)
            print_e("Can't update file header\n");
    }

    if (fi->flags & O_TRUNC) {
        off_t blocks = of->fsize / DATA_FILE_BLOCK_LEN;
        off_t len = HEADER_FILE_LEN +
                blocks * DATA_FILE_BLOCK_LEN;
        print_d("truncate file %s to len: %jd\n",
               of->encrypted_path, len);
        rc = cfs_truncate(of->encrypted_path, len);
        if (!rc)
            print_e("Can't truncate file %s\n", of->encrypted_path);
    }

    /** Update info into another opened file descriptors */
    LIST_FOREACH(cfs->opened_files, le) {
        struct opened_file *rest_of = list_ledata(le);
        if (strcmp(rest_of->encrypted_path, of->encrypted_path) != 0)
            continue;
        memcmp(rest_of->file_header, of->file_header,
               sizeof (struct file_header_format));
        rest_of->fsize = of->fsize;
    }

    return rc;
}


static int fs_getattr(const char *path, STAT *st)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    CFS_STAT cs;
    struct file_header_format *file_header;
    int rc = -1;
    print_d("call fs_getattr '%s'\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }
    print_d("encrypted_path = %s\n", encrypted_path);

    rc = cfs_stat(encrypted_path, &cs);
    if (rc) {
        rc = -ENOENT;
        goto out;
    }

    if (cs.st_mode & S_IFREG) {
        /* find currently file in opened files */
        struct le *le;
        bool found = FALSE;
        LIST_FOREACH(cfs->opened_files, le) {
            struct opened_file *rest_of = list_ledata(le);
            if (strcmp(rest_of->encrypted_path, encrypted_path) == 0) {
                st->st_size = rest_of->fsize;
                found = TRUE;
                break;
            }
        }

        if (!found) {
            file_header = read_file_header(encrypted_path,
                                           cfs->key_file->data_key);
            if (!file_header) {
                print_e("Can't got header file: %s\n", encrypted_path);
                rc = -ENOENT;
                goto out;
            }
            st->st_size = file_header->fsize;
        }
    }

    st->st_gid = cs.st_gid;
    st->st_dev = cs.st_dev;
    st->st_ino = cs.st_ino;
    st->st_mode = cs.st_mode;
    st->st_nlink = cs.st_nlink;
    st->st_rdev = cs.st_rdev;
    st->st_uid = cs.st_uid;
#ifndef _WIN32
    st->st_atime = cs.st_atime;
    st->st_mtime = cs.st_mtime;
    st->st_ctime = cs.st_ctime;
#else
    st->st_atim.tv_sec = cs.st_atime;
    st->st_atim.tv_nsec = 0;
    st->st_ctim.tv_sec = cs.st_ctime;
    st->st_ctim.tv_nsec = 0;
    st->st_mtim.tv_sec = cs.st_mtime;
    st->st_mtim.tv_nsec = 0;
#endif
#ifdef __APPLE__
    st->st_blksize = 0;
#endif

    rc = 0;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_fgetattr(const char *path, STAT *st, struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    STAT cs;
    struct file_header_format *file_header;
    int rc = -1;
    print_d("call fs_fgetattr '%s', size = %ld\n", path, of->fsize);

    rc = fstat(of->fd, &cs);
    if (rc) {
        rc = -ENOENT;
        goto out;
    }

    if (cs.st_mode & S_IFREG)
        st->st_size = of->fsize;

    st->st_uid = cs.st_uid;
    st->st_gid = cs.st_gid;
    st->st_mode = cs.st_mode;
    st->st_nlink = cs.st_nlink;
#ifdef __APPLE__
    st->st_blksize = 0;
#endif
#ifndef _WIN32
    st->st_atime = cs.st_atime;
    st->st_mtime = cs.st_mtime;
    st->st_ctime = cs.st_ctime;
#else
    st->st_atim.tv_sec = cs.st_atim.tv_sec;
    st->st_atim.tv_nsec = cs.st_atim.tv_nsec;
    st->st_ctim.tv_sec = cs.st_ctim.tv_sec;
    st->st_ctim.tv_nsec = cs.st_ctim.tv_nsec;
    st->st_mtim.tv_sec = cs.st_mtim.tv_sec;
    st->st_mtim.tv_nsec = cs.st_mtim.tv_nsec;
#endif

    rc = 0;
out:
    return rc;
}


static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    DIR *dir;
    struct dirent *ent;
    int rc = -1;

    print_d("fs_readdir %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    dir = opendir(encrypted_path);
    if (!dir) {
        print_e("Can't open path %s\n", encrypted_path);
        goto out;
    }

    while ((ent = readdir(dir)) != NULL) {
        char *name;

        if (strcmp(ent->d_name, ".") == 0 ||
            strcmp(ent->d_name, "..") == 0) {
            filler(buf, ent->d_name, NULL, 0);
            continue;
        }

        /** skip file names starting with dot; */
        if (ent->d_name[0] == '.')
            continue;

        /** skip desktop.ini on windows; */
        if (!strcmp(ent->d_name, "desktop.ini"))
            continue;

        name = decrypt_file_name(cfs, ent->d_name);
        if (!name) {
            print_e("Can't decrypt file name %s\n", ent->d_name);
            continue;
        }
        filler(buf, name, NULL, 0);
        kmem_deref(&name);
    }
    closedir(dir);
    rc = 0;
out:
    kmem_deref(&encrypted_path);
    return rc;
}



static int fs_open(const char *path, struct fuse_file_info *fi)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    struct opened_file *of = NULL;
    struct buf *tweak_buf = NULL;
    char *encrypted_path = NULL;
    int rc = -1;

    print_d("--- fs_open path = %s, fi->flags = 0x%x\n",
            path, fi->flags);
    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    of = kzref_alloc(sizeof *of, opened_file_destructor);
    if (!of) {
        print_e("can't alloc opened_file\n");
        goto out;
    }
    fi->fh = (uint64_t)of;
    of->encrypted_path = kmem_ref(encrypted_path);
    of->file_path = kref_strdub(path);
#ifndef _WIN32
    of->flags |= O_DSYNC;
#endif
    of->flags = fi->flags;
    of->cfs = cfs;

    of->file_header = read_file_header(of->encrypted_path,
                                       cfs->key_file->data_key);
    if (!of->file_header) {
        print_e("can't read file header\n");
        goto out;
    }
    of->fsize = of->file_header->fsize;
    print_d("of->fsize = %ld\n", of->fsize);

    tweak_buf = buf_cpy(of->file_header->tweak,
                        sizeof of->file_header->tweak);
    if (!tweak_buf) {
        print_e("can't copy tweak\n");
        goto out;
    }

    of->encrypher = crypher_aes256xts_create(cfs->key_file->data_key,
                                             tweak_buf, 1);

    of->decrypher = crypher_aes256xts_create(cfs->key_file->data_key,
                                             tweak_buf, 0);

    of->fd = cfs_open(of->encrypted_path, O_RDWR);
    if (of->fd <= 0) {
        rc = -errno;
        print_e("can't open %s\n", of->encrypted_path);
        goto out;
    }

    of->fi = fi;

    list_append(cfs->opened_files, &of->le, kmem_ref(of));
    rc = 0;
out:
    kmem_deref(&of);
    kmem_deref(&encrypted_path);
    kmem_deref(&tweak_buf);
    return rc;
}


static int fs_release(const char *path, struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    int rc = 0;
    print_d("fs_release %s\n", path);
    kmem_deref(&of);
    return 0;
}


static int fs_read(const char *path, char *buf,
                   size_t size, off_t offset,
                   struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    int rc;
    off_t block_num;
    struct buf *data_block = NULL;
    uint available_block_data_len;
    uint part_size, block_offset;
    int read_size = -1;
    off_t fpos_block_num;
    uint fpos_block_offset;

    print_d("--- fs_read %s, offset = %jd, size = %zd\n", path, offset, size);

    if (offset >= of->fsize)
        offset = of->fsize;

    fpos_block_num = offset / DATA_FILE_BLOCK_LEN;
    fpos_block_offset = offset - (fpos_block_num * DATA_FILE_BLOCK_LEN);

    print_d("fpos_block_num = %jd\n", fpos_block_num);
    print_d("fpos_block_offset = %d\n", fpos_block_offset);
    print_d("of->fsize = %jd\n", of->fsize);

    available_block_data_len = DATA_FILE_BLOCK_LEN - fpos_block_offset;

    if (!of->fsize) {
        read_size = 0;
        print_d("read_size = %d\n", read_size);
        goto out;
    }

    print_d("loading data block %jd\n", fpos_block_num);
    data_block = load_data_block(of, fpos_block_num);
    if (!data_block) {
        print_e("Can't load data block\n");
        goto out;
    }

    if (offset + size > of->fsize)
        size = of->fsize - offset;

    part_size = size < available_block_data_len ? size : available_block_data_len;
    block_offset = fpos_block_offset;
    read_size = 0;
    block_num = fpos_block_num;

    print_d("available_block_data_len = %d\n", available_block_data_len);
    print_d("part_size = %d\n", part_size);
    print_d("block_offset = %d\n", block_offset);

    print_d("! while !\n");
    while (size > 0) {
        bool load_next_block_flag = FALSE;
        print_d("do: \n");

        print_d("load_data_block, block_num = %jd\n", block_num);
        data_block = load_data_block(of, block_num++);
        if (!data_block) {
            print_d("Can't load data block number %jd\n", block_num - 1);
            break;
        }

        print_d("memcpy read_size = %d, block_offset = %d, part_size = %d\n",
                read_size, block_offset, part_size);

        memcpy(buf + read_size,
               data_block->data + block_offset,
               part_size);
        kmem_deref(&data_block);

        size -= part_size;
        read_size += part_size;

        print_d("size = %ld\n", size);

        block_offset = 0;

        if ((offset + read_size) < of->fsize)
            load_next_block_flag = TRUE;

        print_d("load_next_block_flag = %d\n", load_next_block_flag);
        part_size = size < DATA_FILE_BLOCK_LEN ?
                    size : DATA_FILE_BLOCK_LEN;
        print_d("part_size = %d\n", part_size);

        if (!load_next_block_flag)
            break;
    }
    print_d("! end while !\n");

    print_d("read_size = %d\n", read_size);
out:
    print_d("fs_read %s, fd=%d, offset = %jd, size = %zd\n", path, of->fd, offset, size);
    kmem_deref(&data_block);
    return read_size;
}


static int fs_write(const char *path, const char *buf,
                    size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    struct cryptfs *cfs = of->cfs;
    struct le *le;
    int rc;
    off_t block_num;
    off_t new_size;
    struct buf *data_block = NULL;
    uint free_block_space;
    uint part_size, block_offset;
    int wrote_size = -1;
    off_t fpos_block_num, last_block;
    uint fpos_block_offset;

    print_d("--- fs_write %s, fsize = %ld, offset = %jd, size = %zd\n",
            path, of->fsize, offset, size);

    fpos_block_num = offset / DATA_FILE_BLOCK_LEN;
    fpos_block_offset = offset - (fpos_block_num * DATA_FILE_BLOCK_LEN);
    last_block = (of->fsize - 1) / DATA_FILE_BLOCK_LEN;

    print_d("fpos_block_num = %jd\n", fpos_block_num);
    print_d("fpos_block_offset = %d\n", fpos_block_offset);
    print_d("last_block  = %jd\n", last_block);
    print_d("of->fsize = %jd\n", of->fsize);

    free_block_space = DATA_FILE_BLOCK_LEN - fpos_block_offset;

    if (of->fsize && (fpos_block_num <= last_block)) {
        print_d("loading data block %jd\n", fpos_block_num);
        data_block = load_data_block(of, fpos_block_num);
        if (!data_block) {
            print_e("Can't load data block\n");
            goto out;
        }
    } else {
        print_d("alloc new data block\n");
        data_block = bufz_alloc(DATA_FILE_BLOCK_LEN);
        if (!data_block) {
            print_e("Can't alloc for new data block\n");
            goto out;
        }
    }

    part_size = size < free_block_space ? size : free_block_space;
    block_offset = fpos_block_offset;
    wrote_size = 0;
    block_num = fpos_block_num;

    print_d("free_block_space = %d\n", free_block_space);
    print_d("part_size = %d\n", part_size);
    print_d("block_offset = %d\n", block_offset);

    print_d("! while !\n");
    while (size > 0) {
        bool load_next_block_flag = FALSE;
        print_d("do: \n");

        print_d("memcpy block_offset = %d, wrote_size = %d, part_size = %d\n",
                block_offset, wrote_size, part_size);
        memcpy(data_block->data + block_offset,
               buf + wrote_size, part_size);
        size -= part_size;
        wrote_size += part_size;

        print_d("save_data_block, block_num = %jd\n", block_num);
        rc = save_data_block(of, block_num, data_block);
        if (rc) {
            print_d("Can't save data block number %jd\n", block_num - 1);
            break;
        }

        block_offset = 0;
        kmem_deref(&data_block);

        if ((offset + wrote_size) < of->fsize)
            load_next_block_flag = TRUE;

        if (block_num == last_block)
            load_next_block_flag = FALSE;

        if (load_next_block_flag && (fi->flags & O_TRUNC)) {
            off_t remainder = of->fsize - (offset + wrote_size);
            if (remainder <= DATA_FILE_BLOCK_LEN)
                load_next_block_flag = FALSE;
        }

        block_num ++;

        print_d("load_next_block_flag = %d\n", load_next_block_flag);

        if (load_next_block_flag) {
            print_d("load next block number %jd\n", block_num);
            data_block = load_data_block(of, block_num);
            if (!data_block) {
                print_d("Can't load data block %jd\n", block_num);
                goto out;
            }
        } else {
            print_d("allocate for next block\n");
            data_block = bufz_alloc(DATA_FILE_BLOCK_LEN);
            if (!data_block) {
                print_e("Can't alloc for new data block\n");
                goto out;
            }
        }
        part_size = size < DATA_FILE_BLOCK_LEN ?
                    size : DATA_FILE_BLOCK_LEN;
        print_d("part_size = %d\n", part_size);
    }
    print_d("! end while !\n");

    new_size = (offset + wrote_size) > of->fsize ?
               (offset + wrote_size) : of->fsize;

    if ((fi->flags & O_TRUNC) &&
            (offset + wrote_size) > of->fsize) {
        new_size = offset + wrote_size;
    }
    print_d("new_size = %jd\n", new_size);
    of->fsize = new_size;

#ifdef _WIN32
     cfs_fsync(of->fd);
#endif
    /* Synchronize all opened files with new file size */
    LIST_FOREACH(cfs->opened_files, le) {
        struct opened_file *rest_of = list_ledata(le);
        if (strcmp(rest_of->encrypted_path, of->encrypted_path) == 0)
            rest_of->fsize = of->fsize;
    }

out:
    print_d("fs_write %s, fd=%d, fsize = %ld, offset = %jd, size = %zd\n", path, of->fd, of->fsize, offset, size);
    kmem_deref(&data_block);
    return wrote_size;
}


static int fs_mkdir(const char* path, mode_t mode)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_mkdir %s\n", path);

#ifdef __unix__))
    if (!memcmp(path, "/.Trash", 6)) {
        rc = -EACCES;
        goto out;
    }
#endif

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = cfs_mkdir(encrypted_path, mode);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_mknod(const char* path, mode_t mode, dev_t dev)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    struct file_header_format file_header;
    struct buf *tweak = NULL;
    char *encrypted_path = NULL;
    int rc = -1;
    int fd;
    print_d("fs_mknod %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }
    fd = cfs_creat(encrypted_path, mode);
    if (fd < 0) {
        rc = -errno;
        print_e("can't open %s for create file header\n", encrypted_path);
        goto out;
    }
    tweak = make_rand_buf(DATA_FILE_TWEAK_LEN);
    file_header.fsize = 0;
    memcpy(&file_header.tweak, tweak->data, tweak->len);
    rc = write_file_header(fd, &file_header,
                           cfs->key_file->data_key);
    if (rc) {
        print_e("can't write file_header in file %s\n", encrypted_path);
        goto out;
    }
    cfs_close(fd);

    rc = 0;
out:
    kmem_deref(&tweak);
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_rename(const char* old, const char* new)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_old = NULL, *encrypted_new = NULL;
    int rc = -1;
    print_d("fs_rename %s to %s\n", old, new);

    encrypted_old = encrypt_path(cfs, old, cfs->folder);
    if (!encrypted_old) {
        print_e("Can't encrypt old path %s\n", old);
        goto out;
    }

    encrypted_new = encrypt_path(cfs, new, cfs->folder);
    if (!encrypted_new) {
        print_e("Can't encrypt old path %s\n", new);
        goto out;
    }

#ifdef _WIN32
    struct le *le;
    /** Close each fd associated with requested file; */
    LIST_FOREACH(cfs->opened_files, le) {
            struct opened_file *rest_of = list_ledata(le);
            if (strcmp(rest_of->encrypted_path, encrypted_old) == 0)
                if (cfs_close(rest_of->fd) == -1)
                    print_e("Can't close %d\n", rest_of->fd);
        }
#endif
    rc = rename(encrypted_old, encrypted_new);
    if (rc) {
        rc = -errno;
        print_e("Can't rename %s: ", old);
    }

#ifdef _WIN32
    /** Reopen previosly closed fd's; */
    LIST_FOREACH(cfs->opened_files, le) {
            struct opened_file *rest_of = list_ledata(le);
            if (strcmp(rest_of->encrypted_path, encrypted_old) != 0)
                continue;

            rest_of->fd = cfs_open(encrypted_new, rest_of->flags);
            if (rest_of->fd == -1)
                print_e("Can't reopen %s\n", encrypted_new);
            kmem_deref(&rest_of->encrypted_path);
            rest_of->encrypted_path = kmem_ref(encrypted_new);
        }
#endif
out:
    kmem_deref(&encrypted_old);
    kmem_deref(&encrypted_new);
    return rc;
}


static int fs_rmdir(const char* path)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_rmdir %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = cfs_rmdir(encrypted_path);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_unlink(const char* path)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_unlink %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = cfs_unlink(encrypted_path);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


#ifndef _WIN32
static int fs_lock(const char *path, struct fuse_file_info *fi,
                   int cmd, struct flock *fl)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    print_d("call fs_lock %s\n", path);
    return flock(of->fd, cmd);
}


static int fs_utime(const char *path, struct utimbuf *time)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_utime %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = utime(encrypted_path, time);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_readlink(const char *path, char *buf, size_t size)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_readlink %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = readlink(encrypted_path, buf, size - 1);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_chmod(const char *path, mode_t mode)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_chmod %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = chmod(encrypted_path, mode);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_chown(const char *path, uid_t uid, gid_t gid)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_chown %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = lchown(encrypted_path, uid, gid);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_link(const char *from, const char *to)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_from = NULL, *encrypted_to = NULL;
    int rc = -1;
    print_d("fs_link %s to %s\n", from, to);

    encrypted_from = encrypt_path(cfs, from, cfs->folder);
    if (!encrypted_from) {
        print_e("Can't encrypt path_from %s\n", from);
        goto out;
    }

    encrypted_to = encrypt_path(cfs, to, cfs->folder);
    if (!encrypted_to) {
        print_e("Can't encrypt path_to %s\n", to);
        goto out;
    }

    rc = link(encrypted_from, encrypted_to);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_from);
    kmem_deref(&encrypted_to);
    return rc;
}


static int fs_symlink(const char *from, const char *to)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path_to = NULL;
    int rc = -1;
    print_d("fs_symlink %s to %s\n", from, to);

    encrypted_path_to = encrypt_path(cfs, to, cfs->folder);
    if (!encrypted_path_to) {
        print_e("Can't encrypt path %s\n", encrypted_path_to);
        goto out;
    }

    // TODO: Needs to support uncrypted symlink.
    // This feature is not worked correctly
    rc = symlink(from, encrypted_path_to);
    if (rc == -1)
            return -errno;
out:
    kmem_deref(&encrypted_path_to);
    return rc;
}


#ifndef __APPLE__
/** Set extended attributes */
static int fs_setxattr(const char *path, const char *name,
                       const char *value, size_t size, int flags)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_setxattr %s, name = %s, value=%s\n", path, name, value);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = setxattr(encrypted_path, name, value, size, flags);
out:
    kmem_deref(&encrypted_path);
    return rc;
}

/** Get extended attributes */
static int fs_getxattr(const char *path, const char *name,
                       char *value, size_t size)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_getxattr %s, name = %s\n", path, name);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = getxattr(encrypted_path, name, value, size);
    print_d("value = %s\n", value);
out:
    kmem_deref(&encrypted_path);
    return rc;
}
#else
/** Set extended attributes */
static int fs_setxattr(const char *path, const char *name,
                       const char *value, size_t size, u_int32_t position, int flags)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_setxattr %s, name = %s, value=%s\n", path, name, value);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = setxattr(encrypted_path, name, value, size, position, flags);
out:
    kmem_deref(&encrypted_path);
    return rc;
}

/** Get extended attributes */
static int fs_getxattr(const char *path, const char *name,
                       char *value, size_t size, u_int32_t position, int options)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_getxattr %s, name = %s\n", path, name);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = getxattr(encrypted_path, name, value, size, position, options);
    print_d("value = %s\n", value);
out:
    kmem_deref(&encrypted_path);
    return rc;
}
#endif
#endif


static int fs_statfs(const char *path, struct statvfs *stbuf)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_statfs %s\n", path);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = cfs_statvfs(encrypted_path, stbuf);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_truncate(const char *path, off_t new_size)
{
    struct opened_file *of = NULL;
    off_t blocks_cnt, new_blocks_cnt, append_blocks_cnt, i;
    struct fuse_file_info fi;
    struct cryptfs *cfs;
    struct le *le;
    int rc = -1;
    print_d("--- fs_truncate %s, new_size = %ld\n", path, new_size);

    memset(&fi, 0, sizeof fi);
    fi.flags = O_RDWR;
    rc = fs_open(path, &fi);
    if (rc) {
        print_e("Can't open file %s\n", path);
        goto out;
    }
    of = (struct opened_file *)fi.fh;
    cfs = of->cfs;

    print_d("of->fsize = %ld\n", of->fsize);
    if (of->fsize == new_size) {
        rc = 0;
        goto out;
    }

    blocks_cnt = of->fsize / DATA_FILE_BLOCK_LEN;
    if (!blocks_cnt && of->fsize)
        blocks_cnt = 1;

    new_blocks_cnt = new_size / DATA_FILE_BLOCK_LEN;
    if (new_blocks_cnt * DATA_FILE_BLOCK_LEN < new_size)
        new_blocks_cnt += 1;

    print_d("blocks_cnt = %jd\n", blocks_cnt);
    print_d("new_blocks_cnt = %jd\n", new_blocks_cnt);

    if (new_blocks_cnt <= blocks_cnt) {
        rc = cfs_truncate(of->encrypted_path,
                      HEADER_FILE_LEN +
                      new_blocks_cnt * DATA_FILE_BLOCK_LEN);
        if (rc)
            rc = -errno;

        goto out;
    }

    if (blocks_cnt == new_blocks_cnt) {
        rc = update_file_header(of, new_size);
        if (rc)
            print_e("Can't update file header %s\n", path);

        goto out;
    }

    /* if new_blocks_cnt > blocks_cnt */
    append_blocks_cnt = new_blocks_cnt - blocks_cnt;
    for (i = 0; i < append_blocks_cnt; i++) {
        struct buf *block = bufz_alloc(DATA_FILE_BLOCK_LEN);
        if (!block) {
            rc = -1;
            print_e("Can't alloc for new block\n");
            goto out;
        }

        rc = save_data_block(of, blocks_cnt + i, block);
        kmem_deref(&block);
        if (rc) {
            print_e("Can't save new block\n");
            goto out;
        }
    }

    rc = update_file_header(of, new_size);
    if (rc)
        print_e("Can't update file header %s\n", path);

    rc = 0;
out:
    if (!of)
        return rc;

#ifdef _WIN32
    cfs_fsync(of->fd);
#endif
    /* Update fsize for all descriptors for current truncated file */
    LIST_FOREACH(cfs->opened_files, le) {
        struct opened_file *of_item = list_ledata(le);
        if (strcmp(of_item->file_path, of->file_path) == 0)
            of_item->fsize = new_size;
    }

    kmem_deref(&of);
    return rc;
}


static int fs_fsync(const char *path, int a, struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    struct cryptfs *cfs = of->cfs;
    struct le *le;
    int rc, ret = 0;

    print_d("call fs_fsync %s\n", path);
    LIST_FOREACH(cfs->opened_files, le) {
        struct opened_file *rest_of = list_ledata(le);
        rc = fs_flush(rest_of->file_path, rest_of->fi);
        if (rc) {
            print_e("Can't flush file %s\n", rest_of->encrypted_path);
            ret = rc;
        }

        rc = cfs_fsync(rest_of->fd);
        if (rc)
            ret = rc;
    }

    return ret;
}


static int fs_access(const char *path, int permission)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path = NULL;
    int rc = -1;
    print_d("fs_access %s, permission = 0x%x\n", path, permission);

    encrypted_path = encrypt_path(cfs, path, cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = cfs_access(encrypted_path, permission);
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static struct fuse_operations fs_operations =
{
    .getattr    = fs_getattr,
    .fgetattr   = fs_fgetattr,
    .readdir    = fs_readdir,
    .open       = fs_open,
    .release    = fs_release,
    .read       = fs_read,
    .write      = fs_write,
    .mkdir      = fs_mkdir,
    .mknod      = fs_mknod,
    .rename     = fs_rename,
    .rmdir      = fs_rmdir,
    .unlink     = fs_unlink,
    .statfs     = fs_statfs,
    .truncate   = fs_truncate,
    .flush      = fs_flush,
    .fsync      = fs_fsync,
    .access     = fs_access,
#ifndef _WIN32
    .chown      = fs_chown,
    .link       = fs_link,
    .symlink    = fs_symlink,
    .readlink   = fs_readlink,
    .chmod      = fs_chmod,
    .lock       = fs_lock,
    .utime      = fs_utime,
#ifndef __APPLE__
    .setxattr   = fs_setxattr,
    .getxattr   = fs_getxattr,
#endif
#endif
};


struct cryptfs *cryptfs_create(const char *crypted_folder, const char *keys_file_name)
{
    struct cryptfs *cfs = NULL;

    if (!dir_exist(crypted_folder)) {
        print_e("folder %s is not exist\n", crypted_folder);
        goto out;
    }

    if (!file_exist(keys_file_name)) {
        print_e("%s file is not exist\n", keys_file_name);
        goto out;
    }

    cfs = kzref_alloc(sizeof(struct cryptfs), cryptfs_destructor);
    if (!cfs) {
        print_e("alloc cryptfs error\n");
        goto out;
    }

#ifndef _WIN32
    cfs->folder = kref_strdub(crypted_folder);
#else
    cfs->folder = kref_sprintf("\\\\?\\%s", crypted_folder);
    for(char *p = (char *)cfs->folder; *p; p++)
        if (*p == '/')
            *p = '\\';
#endif
    if (!cfs->folder) {
        print_e("Can't copy crypted_folder\n");
        goto out;
    }

    cfs->keys_file_name = kref_strdub(keys_file_name);
    if (!cfs->keys_file_name) {
        print_e("Can't copy file name\n");
        goto out;
    }

    cfs->opened_files = list_create();
    if (!cfs->opened_files) {
        print_e("Can't create opened_files list\n");
        goto out;
    }

    return cfs;
out:
    kmem_deref(&cfs);
    return NULL;
}


int cryptfs_mount(struct cryptfs *cfs, const char *mount_point_folder, const char *password)
{
    struct buf *key_file_key = NULL;
    struct buf *pass = NULL;
#ifdef __APPLE__
    char *mount_point = strdup(mount_point_folder);
    void* fuse_args_osx = kref_sprintf("volname=%s", basename(mount_point));
    print_d("mount_point name is %s\n", basename(mount_point));
    free(mount_point);
    char *argv[] = {"test", "-o", fuse_args_osx, NULL};
    struct fuse_args fuse_args = FUSE_ARGS_INIT(3, argv);
#else
#ifdef __unix__
    struct fuse_args fuse_args = FUSE_ARGS_INIT(0, NULL);
#else
    char *argv[] = {"tst", "-s", NULL};
    struct fuse_args fuse_args = FUSE_ARGS_INIT(2, argv);
#endif
#endif
    int rc = -1;

    pass = buf_strdub(password);
    if (!pass) {
        print_e("Can't alloc for pass\n");
        goto out;
    }

    key_file_key = sha256(pass, KEY_FILE_KEY_LEN);
    if (!key_file_key) {
        print_e("Can't got md5 for key\n");
        return -1;
    }

    rc = key_file_load(cfs->keys_file_name, key_file_key, &cfs->key_file);
    switch (rc) {
    case -1:
        print_e("Can't load and encrypt key file\n");
        goto out;

    case -2:
        print_e("key file corrupt or incorrect password\n");
        goto out;
    }

    cfs->header_key = sha256(cfs->key_file->data_key, HEADER_FILE_KEY_LEN);
    if (!cfs->header_key) {
        print_e("Can't got md5 for header_key\n");
        goto out;
    }

    cfs->file_name_key = sha256(cfs->header_key, FILE_NAME_KEY_LEN);
    if (!cfs->file_name_key) {
        print_e("Can't got md5 for file_name_key\n");
        goto out;
    }

    cfs->mount_point_folder = kref_strdub(mount_point_folder);
    if (!cfs->mount_point_folder) {
        print_e("Can't copy crypted_folder\n");
        goto out;
    }

#ifdef __APPLE__
    void *cmd = kref_sprintf("umount -f %s", cfs->mount_point_folder);
    rc = system(cmd);
    print_d("%s return %d\n", cmd, rc);
    kmem_deref(&cmd);
#else
    fuse_unmount(mount_point_folder, NULL);
#endif

    cfs->fc = fuse_mount(mount_point_folder, &fuse_args);
    if (!cfs->fc) {
        print_d("fuse_mount error\n");
        goto out;
    }
    cfs->fuse = fuse_new(cfs->fc, &fuse_args, &fs_operations,
                         sizeof fs_operations, cfs);
    if (!cfs->fuse) {
        print_d("fuse_new error\n");
        goto out;
    }

    rc = 0;
out:
    buf_deref(&pass);
    buf_deref(&key_file_key);
#ifdef __APPLE__
    kmem_deref(&fuse_args_osx);
#endif
    return rc;
}

int cryptfs_ummount(struct cryptfs *cfs)
{
    print_d("in unmount\n");
#ifdef __APPLE__
    struct fuse_session *fs = fuse_get_session(cfs->fuse);
    struct fuse_chan *ch = fuse_session_next_chan(fs, NULL);
    fuse_session_remove_chan(ch);
    fuse_destroy(cfs->fuse);
    fuse_unmount(cfs->mount_point_folder, ch);
#else
    fuse_unmount(cfs->mount_point_folder, cfs->fc);
#endif
    return 0;
}

void cryptfs_loop(struct cryptfs *cfs)
{
    print_d("in cryptfs_loop\n");
    int rc = fuse_loop(cfs->fuse);
    print_d("after cryptfs_loop\n");
}

int cryptfs_generate_key_file(const char *password, const char *filename)
{
    print_d("cryptfs_generate_key_file got: %s %s\n", password, filename);
    struct buf *key = NULL;
    struct buf *pass = NULL;
    struct key_file key_file;
    int rc = -1;

    key_file.data_key = make_rand_buf(DATA_FILE_KEY_LEN);
    if (!key_file.data_key) {
        print_e("Can't generate new data key\n");
        goto out;
    }

    key_file.file_iv = make_rand_buf(FILE_NAME_IV_LEN);
    if (!key_file.file_iv) {
        print_e("Can't generate file IV key\n");
        goto out;
    }

    pass = buf_strdub(password);
    if (!pass)
        goto out;

    key = sha256(pass, KEY_FILE_KEY_LEN);
    if (!key) {
        print_e("Can't got sha256 for key\n");
        goto out;
    }

    rc = key_file_save(&key_file, filename, key);
    if (rc) {
        print_e("Can't generate key file\n");
        goto out;
    }

    rc = 0;
out:
    buf_deref(&key);
    buf_deref(&pass);
    buf_deref(&key_file.data_key);
    buf_deref(&key_file.file_iv);
    return rc;
}

void cryptfs_free(struct cryptfs* cfs)
{
    kmem_deref(&cfs);
}
