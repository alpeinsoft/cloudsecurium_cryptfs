#ifndef _CRYPTFS_H
#define _CRYPTFS_H

struct cryptfs {
    char *key_filename;

    struct key_file *key_file;
    struct buf *header_key;
    struct buf *file_name_key;

    char *folder;
    char *mount_point_folder;
    struct fuse_chan *fc;
    struct fuse *fuse;
};


#define HEADER_FILE_IV_LEN 12
#define HEADER_FILE_KEY_LEN 32
#define KEY_FILE_KEY_LEN 32
#define DATA_FILE_KEY_LEN 64

struct cryptfs *cryptfs_create(char *crypted_folder, char *key_filename);
int cryptfs_mount(struct cryptfs *cryptfs, char *mount_point_path, char *password);
int cryptfs_ummount(struct cryptfs *cryptfs);
void cryptfs_loop(struct cryptfs *cryptfs);
int cryptfs_generate_key_file(char *password, char *filename);

#endif // _CRYPTFS_H
