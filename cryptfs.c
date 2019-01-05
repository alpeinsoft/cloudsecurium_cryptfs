#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include <dirent.h>
#include "kref_alloc.h"
#include "key_file.h"
#include "crypher.h"
#include "cryptfs.h"
#include "buf.h"

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
};

void opened_file_destructor(void *mem)
{
    struct opened_file *of = (struct opened_file *)mem;
    close(of->fd);
    list_unlink(&of->le);
    kmem_deref(&of->file_path);
    kmem_deref(&of->encrypted_path);
}


static int fs_getattr(const char *path, struct stat *st)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    struct stat cs;
    int rc = -1;
    printf("call fs_getattr '%s'\n", path);
    encrypted_path = encrypt_path(path,
                                  cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = stat(encrypted_path, &cs);
    if (rc) {
        rc = -ENOENT;
//        print_e("Can't stat %s\n", encrypted_path);
        goto out;
    }

    st->st_uid = cs.st_uid;
    st->st_gid = cs.st_gid;
    st->st_atime = cs.st_atime;
    st->st_mtime = cs.st_mtime;
    st->st_mode = cs.st_mode;
    st->st_nlink = cs.st_nlink;
    st->st_size = cs.st_size;

    rc = 0;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    DIR *dir;
    struct dirent *ent;
    int rc = -1;


    printf("fs_readdir %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key, cfs->folder);
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

        name = decrypt_file_name(ent->d_name, cfs->file_name_key);
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
    struct opened_file *of;
    char *encrypted_path;
    int rc = -1;
    int fd;

    printf("fs_open path = %s\n", path);
    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
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
    of->flags = fi->flags;

    of->fd = open(of->encrypted_path, fi->flags);
    if (fd < 0) {
        print_e("can't open %s\n", of->encrypted_path);
        goto out;
    }

    list_append(cfs->opened_files, &of->le, of);

    rc = 0;
    kmem_ref(of);
out:
    kmem_deref(&of);
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_release(const char *path, struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    printf("fs_release %s\n", path);
    kmem_deref(&of);
}


static int fs_read(const char *path, char *buf,
                   size_t size, off_t offset,
                   struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    int read_size = -1;
    printf("fs_read %s\n", path);
    read_size = read(of->fd, buf, size);
    return read_size;
}


static int fs_write(const char *path, const char *buf,
                    size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    struct opened_file *of = (struct opened_file *)fi->fh;
    int wrote_size = -1;
    printf("fs_write %s\n", path);
    wrote_size = write(of->fd, buf, size);
    return wrote_size;
}


static int fs_mkdir(const char* path, mode_t mode)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    int rc = -1;
    printf("fs_mkdir %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = mkdir(encrypted_path, mode);
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
    char *encrypted_path;
    int rc = -1;
    printf("fs_mknod %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = mknod(encrypted_path, mode, dev);
    if (rc) {
        rc = -errno;
        goto out;
    }
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_rename(const char* old, const char* new)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_old, *encrypted_new;
    int rc = -1;
    printf("fs_rename %s to %s\n", old, new);

    encrypted_old = encrypt_path(old, cfs->file_name_key,
                                 cfs->folder);
    if (!encrypted_old) {
        print_e("Can't encrypt old path %s\n", old);
        goto out;
    }

    encrypted_new = encrypt_path(new, cfs->file_name_key,
                                 cfs->folder);
    if (!encrypted_new) {
        print_e("Can't encrypt old path %s\n", new);
        goto out;
    }

    rc = rename(encrypted_old, encrypted_new);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_old);
    kmem_deref(&encrypted_new);
    return rc;
}


static int fs_rmdir(const char* path)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    int rc = -1;
    printf("fs_rmdir %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = rmdir(encrypted_path);
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
    char *encrypted_path;
    int rc = -1;
    printf("fs_unlink %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = unlink(encrypted_path);
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
    char *encrypted_path;
    int rc = -1;
    printf("fs_chmod %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
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
    char *encrypted_path;
    int rc = -1;
    printf("fs_chown %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
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
    char *encrypted_from, *encrypted_to;
    int rc = -1;
    printf("fs_link %s to %s\n", from, to);

    encrypted_from = encrypt_path(from, cfs->file_name_key,
                                 cfs->folder);
    if (!encrypted_from) {
        print_e("Can't encrypt path_from %s\n", from);
        goto out;
    }

    encrypted_to = encrypt_path(to, cfs->file_name_key,
                                 cfs->folder);
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
    char *encrypted_from, *encrypted_to;
    int rc = -1;
    printf("fs_symlink %s to %s\n", from, to);
    return 0;
}


static int fs_statfs(const char *path, struct statvfs *stbuf)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    int rc = -1;
    printf("fs_statfs %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    rc = statvfs(encrypted_path, stbuf);
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
    char *encrypted_path;
    int rc = -1;
    printf("fs_readlink %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
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


static int fs_truncate(const char *path, off_t size)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    int rc = -1;
    printf("fs_truncate %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
    if (!encrypted_path) {
        print_e("Can't encrypt path %s\n", path);
        goto out;
    }

    // TODO:
    rc = truncate(encrypted_path, size);
    if (rc)
        rc = -errno;
out:
    kmem_deref(&encrypted_path);
    return rc;
}


static int fs_utime(const char *path, struct utimbuf *time)
{
    struct cryptfs *cfs = (struct cryptfs *)
                           fuse_get_context()->private_data;
    char *encrypted_path;
    int rc = -1;
    printf("fs_utime %s\n", path);

    encrypted_path = encrypt_path(path, cfs->file_name_key,
                                  cfs->folder);
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


static struct fuse_operations fs_operations =
{
    .getattr    = fs_getattr,
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
    .chmod      = fs_chmod,
    .chown      = fs_chown,
    .link       = fs_link,
    .symlink    = fs_symlink,
    .statfs     = fs_statfs,
    .readlink   = fs_readlink,
    .truncate   = fs_truncate,
    .utime      = fs_utime,
};


struct cryptfs *cryptfs_create(char *crypted_folder, char *keys_file_name)
{
    struct cryptfs *cfs;

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

    cfs->folder = kref_strdub(crypted_folder);
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

    rc = key_file_load(cfs->keys_file_name, key, &cfs->key_file);
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

    cfs->file_name_key = md5sum(cfs->key_file->header_iv, 16);
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

