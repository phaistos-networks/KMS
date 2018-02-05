include /home/system/Development/Switch/Makefile.dfl
CXXFLAGS=$(CPPFLAGS_SANITY_DEBUG) -I./sss/

all: service client

service: service.o
	$(CC) service.o -o kms $(LDFLAGS_SANITY) -lswitch -pthread $(LDFLAGS_TLS) $(LDFLAGS_MYSQL) sss/*.o

client: client.o
	$(CC) client.o -o client $(LDFLAGS_SANITY) -lswitch -lpthread $(LDFLAGS_TLS) -lz #-shared

clean:
	rm -f *.o

.PHONY: clean
