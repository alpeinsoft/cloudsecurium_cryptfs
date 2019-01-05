#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include "kref_alloc.h"
#include "key_file.h"
#include "crypher.h"
#include "cryptfs.h"
#include "buf.h"

static void cryptfs_destructor(void *mem)
{
    struct cryptfs *cfs = (struct cryptfs *)mem;
    kmem_deref(&cfs->key_filename);
    kmem_deref(&cfs->key_file);
    kmem_deref(&cfs->header_key);
    buf_deref(&cfs->file_name_key);
    kmem_deref(&cfs->folder);
    kmem_deref(&cfs->mount_point_folder);
}



static int fs_getattr(const char *path, struct stat *st)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    printf("call fs_getattr %s\n", path);


    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);

    if ( strcmp( path, "/" ) == 0 ) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 1024;
    }
    return 0;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi)
{
    printf("fs_readdir\n");
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    if (strcmp(path, "/") == 0) {
        filler(buf, "file54", NULL, 0);
        filler(buf, "file349", NULL, 0);
    }
    return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
    printf("fs_open path = %s\n", path);
/*    int f;
    int rc = 0;
    char *crypt_path = crypt_path(path);
    if (!crypt_path) {
        print_e("can't got crypt_path\n");
        goto out;
    }
    f = open(crypt_path, fi->flags);
    if (f < 0) {
        print_e("can't open %s\n", crypt_path);
        goto out;
    }

    rc = 0;
out:
    kmem_deref(&crypt_path);*/
    return 0;
}

/*читаем данные из открытого файла*/
static int fs_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    printf("fs_read\n");
    return 0;
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    printf("fs_write\n");
    return size;
}

static int fs_mkdir(const char* path, mode_t mode)
{
    printf("fs_mkdir\n");
    return 0;
}

static int fs_mknod(const char* path, mode_t mode, dev_t dev)
{
    printf("fs_mknod\n");
    return 0;
}

static int fs_rename(const char* old, const char* new)
{
    printf("fs_rename\n");
    return 0;
}

static int fs_rmdir(const char* path)
{
    printf("fs_rmdir\n");
    return 0;
}

static int fs_unlink(const char* path)
{
    printf("fs_unlink\n");
    return 0;
}

static struct fuse_operations fs_operations =
{
    .getattr    = fs_getattr,
    .readdir    = fs_readdir,
    .open       = fs_open,
    .read       = fs_read,
    .write      = fs_write,
    .mkdir      = fs_mkdir,
    .mknod      = fs_mknod,
    .rename     = fs_rename,
    .rmdir      = fs_rmdir,
    .unlink     = fs_unlink,
};


struct cryptfs *cryptfs_create(char *crypted_folder, char *key_filename)
{
    struct cryptfs *cfs;

    if (!dir_exist(crypted_folder)) {
        print_e("folder %s is not exist\n", crypted_folder);
        goto out;
    }

    if (!file_exist(key_filename)) {
        print_e("%s file is not exist\n", key_filename);
        goto out;
    }

    cfs = kzref_alloc(sizeof(struct cryptfs), cryptfs_destructor);
    if (!cfs) {
        print_e("alloc cryptfs error\n");
        goto out;
    }

    cfs->folder = kref_strdub(crypted_folder);
    if (!cfs->folder) {
        print_e("Can't copy crypted_folder\n");
        goto out;
    }

    cfs->key_filename = kref_strdub(key_filename);
    if (!cfs->key_filename) {
        print_e("Can't copy file name\n");
        goto out;
    }
    return cfs;
out:
    kmem_deref(&cfs);
    return NULL;
}


int cryptfs_mount(struct cryptfs *cfs, char *mount_point_folder, char *password)
{
    struct buf *key;
    struct buf *pass;
    struct fuse_args fuse_args = FUSE_ARGS_INIT(0, NULL);
    int rc = -1;

    pass = buf_strdub(password);
    if (!pass)
        goto out;

    key = md5sum(pass, KEY_FILE_KEY_LEN);
    if (!key) {
        print_e("Can't got md5 for key\n");
        return -1;
    }

    rc = key_file_load(cfs->key_filename, key, &cfs->key_file);
    switch (rc) {
    case -1:
        print_e("Can't load and encrypt key file\n");
        goto out;

    case -2:
        print_e("key file corrupt or incorrect password\n");
        goto out;
    }

    cfs->header_key = md5sum(key, HEADER_FILE_KEY_LEN);
    if (!cfs->header_key) {
        print_e("Can't got md5 for header_key\n");
        goto out;
    }

    cfs->file_name_key = md5sum(cfs->header_key, 16);
    if (!cfs->file_name_key) {
        print_e("Can't got md5 for file_name_key\n");
        goto out;
    }

    cfs->mount_point_folder = kref_strdub(mount_point_folder);
    if (!cfs->mount_point_folder) {
        print_e("Can't copy crypted_folder\n");
        goto out;
    }

    fuse_unmount(mount_point_folder, NULL);

    cfs->fc = fuse_mount(mount_point_folder, &fuse_args);
    if (!cfs->fc) {
        printf("fuse_mount error\n");
        goto out;
    }

    cfs->fuse = fuse_new(cfs->fc, &fuse_args, &fs_operations,
                         sizeof fs_operations, cfs);
    if (!cfs->fuse) {
        printf("fuse_new error\n");
        goto out;
    }

    rc = 0;
out:
    buf_deref(&pass);
    buf_deref(&key);
    return rc;
}

int cryptfs_ummount(struct cryptfs *cfs)
{
    fuse_unmount(cfs->mount_point_folder, cfs->fc);
    kmem_deref(&cfs->key_file);
    buf_deref(&cfs->header_key);
    buf_deref(&cfs->file_name_key);
    buf_deref(&cfs->mount_point_folder);
    return 0;
}

void cryptfs_loop(struct cryptfs *cfs)
{
    fuse_loop(cfs->fuse);
}

int cryptfs_generate_key_file(char *password, char *filename)
{
    struct buf *key;
    struct buf *pass;
    struct key_file key_file;
    int rc = -1;

    key_file.data_key = make_rand_buf(DATA_FILE_KEY_LEN);
    if (!key_file.data_key) {
        print_e("Can't generate new data key\n");
        goto out;
    }

    key_file.header_iv = make_rand_buf(HEADER_FILE_IV_LEN);
    if (!key_file.header_iv) {
        print_e("Can't generate new header IV\n");
        goto out;
    }

    pass = buf_strdub(password);
    if (!pass)
        goto out;

    key = md5sum(pass, KEY_FILE_KEY_LEN);
    if (!key) {
        print_e("Can't got md5 for key\n");
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
    buf_deref(&key_file.header_iv);
    return rc;
}

