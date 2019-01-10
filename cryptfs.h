#ifndef _CRYPTFS_H
#define _CRYPTFS_H


struct cryptfs {
    char *keys_file_name;

    struct key_file *key_file;
    struct buf *header_key;
    struct buf *file_name_key;

    char *folder;
    char *mount_point_folder;
    struct fuse_chan *fc;
    struct fuse *fuse;

    struct list *opened_files;
};


#define HEADER_FILE_IV_LEN 12
#define HEADER_FILE_KEY_LEN 32
#define HEADER_FILE_TAG_LEN AES256GCM_TAG_LEN
#define HEADER_FILE_LEN (HEADER_FILE_IV_LEN + HEADER_FILE_TAG_LEN + \
                         sizeof (struct file_header_format))

#define KEY_FILE_KEY_LEN 32

#define FILE_NAME_KEY_LEN 32
#define FILE_NAME_IV_LEN 12
#define FILE_NAME_TAG_LEN 12


#define DATA_FILE_KEY_LEN 64
#define DATA_FILE_TWEAK_LEN 16
#define DATA_FILE_BLOCK_LEN 16 // Needs 4096

struct file_header_format {
    u8 tweak[DATA_FILE_TWEAK_LEN];
    off_t fsize;
};

struct cryptfs *cryptfs_create(char *crypted_folder, char *keys_file_name);
int cryptfs_mount(struct cryptfs *cryptfs, char *mount_point_path, char *password);
int cryptfs_ummount(struct cryptfs *cryptfs);
void cryptfs_loop(struct cryptfs *cryptfs);
int cryptfs_generate_key_file(char *password, char *filename);

#endif // _CRYPTFS_H
