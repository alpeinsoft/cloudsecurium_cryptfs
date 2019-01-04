
struct cryptfs;

#define HEADER_FILE_IV_LEN 12
#define HEADER_FILE_KEY_LEN 32
#define DATA_FILE_KEY_LEN 64

int cryptfs_create(char *crypted_folder, char *key_file, struct cryptfs **cryptfs);
int cryptfs_mount(struct cryptfs *cryptfs, char *mount_point_path, char *password);
int cryptfs_ummount(struct cryptfs *cryptfs);
void cryptfs_loop(struct cryptfs *cryptfs);

