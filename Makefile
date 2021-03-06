CC=gcc
CFLAGS=  -O3 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -DDEBUG2 -fPIC
OBJECTS= base32.o cryptfs.o key_file.o crypher.o buf.o common.o list.o kref.o kref_alloc.o
LIBS = -L . -lssl -lcrypto -lfuse -lm


# --- targets
all: test
  
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

lib: $(OBJECTS)
	$(CC) $(CFLAGS) -shared -fPIC -o libcryptfs.so $(LIBS) $(OBJECTS)

test: lib test.o
	$(CC) $(CFLAGS) test.o libcryptfs.so -o test $(LIBS) $(OBJECTS)

clean:
	rm -f crypt $(OBJECTS)
	rm test libcryptfs.so
