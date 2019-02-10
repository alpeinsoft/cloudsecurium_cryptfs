

struct cryptfs - Главный дескриптор файловой системы
На каждый аккаунт будет по своему дескриптору. 

Ниже описание API:

int cryptfs_generate_key_file(char *password, char *filename);
Генерирует файл ключа. Вызывается один раз при создании аккаунта.
password - новый пароль
filename - путь к фалйлу ключа
Возвращает 0 в случае успеха


struct cryptfs *cryptfs_create(char *crypted_folder, char *keys_file_name);
Создаёт дескриптор файловой системы и возвращает указатель на него.
Вызывается один раз при запуске программы на каждый аккаунт 
crypted_folder - путь к шифрованному каталогу
keys_file_name - путь к фалйлу ключа


int cryptfs_mount(struct cryptfs *cryptfs, char *mount_point_path, char *password);
Осуществляет монтирование FS.
cryptfs - дескриптор файловой системы
mount_point_path - точка монтирования 
password - пароль к ключу
Возвращает 0 в случае успеха


int cryptfs_ummount(struct cryptfs *cryptfs);
Осуществляет размонтирование FS.
cryptfs - дескриптор файловой системы
Возвращает 0 в случае успеха


void cryptfs_loop(struct cryptfs *cryptfs);
loop функция для обработки событий от FS
Должна встраиваться в отдельный поток.
Для каждого аккаунта должен быть свой поток.
cryptfs - дескриптор файловой системы


Память выделяется внутри API. Например после того как дескриптор cryptfs
стал более ненужен, для освобождения его памяти нужно вызвать 
kmem_deref(&cryptfs);




Для использования CryptFS в исходниках, помимо линковки библиотеки, необходимо прописать 
include "crypytfs.h"