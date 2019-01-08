CC=gcc
CFLAGS=  -O3 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26
OBJECTS= base32.o cryptfs.o key_file.o crypher.o buf.o common.o list.o kref.o kref_alloc.o test.o
LIBS = -L . -lssl -lcrypto -lfuse -lm


# --- targets
all: crypt
crypt: $(OBJECTS)
	$(CC) test.o base32.o cryptfs.o key_file.o crypher.o common.o buf.o list.o kref.o kref_alloc.o -o test $(LIBS)
        
test.o:
	$(CC) $(CFLAGS) -c test.c

kref_alloc.o:
	$(CC) $(CFLAGS) -c kref_alloc.c

list.o:
	$(CC) $(CFLAGS) -c list.c

kref.o:
	$(CC) $(CFLAGS) -c kref.c

common.o:
	$(CC) $(CFLAGS) -c common.c

buf.o:
	$(CC) $(CFLAGS) -c buf.c

crypher.o:
	$(CC) $(CFLAGS) -c crypher.c

key_file.o:
	$(CC) $(CFLAGS) -c key_file.c

cryptfs.o:
	$(CC) $(CFLAGS) -c cryptfs.c

base32.o:
	$(CC) $(CFLAGS) -c base32.c
       
clean:
	rm -f crypt $(OBJECTS)
