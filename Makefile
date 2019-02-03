CC=gcc
CFLAGS=-O3 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26
SOURCES=base32.c cryptfs.c key_file.c crypher.c buf.c common.c list.c kref.c kref_alloc.c

UNAME=S(shell uname)
SOURCES_DIR=$(shell pwd)

#ifeq ($(UNAME),Linux)
    LIBS = -L . -lssl -lcrypto -lfuse -lm
#else ifeq ($(UNAME),Darwin)
#    LIBS = -L . -lssl -lcrypto -losxfuse -lm
#endif

# --- targets
all: lib test
test:
	$(CC) -I$(SOURCES_DIR) -L$(SOURCES_DIR) $(CFLAGS) $(LIBS) -lcryptfs test.c -o test
       
lib:
	$(CC) -shared -fPIC $(CFLAGS) $(LIBS) $(SOURCES) -o libcryptfs.so
       
clean:
	rm -f crypt *o
	rm -f test
	rm -f *.so
