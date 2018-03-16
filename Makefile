HOST:=$(shell hostname)
HOST:=foo

ifeq ($(HOST), origin)
	# running one our development machine
	include /home/system/Development/Switch/Makefile.dfl
	CXXFLAGS=$(CPPFLAGS_SANITY_DEBUG) -I./sss/
	EOBJS:=
	LDFLAGS:=-lswitch
	CLEANUP_EXTRA:=
	# Explicitly using a mySQL 5.7+ distribution client for <=5.6 distribution clients
	# can't connect to mySQL servers via SSL
	MYSQL_LIBS:=/usr/local/mysql-57/lib/libmysqlclient.a
	TARGETS:=service client
else
	CC:=clang
	CXX:=clang++
	CC:=$(CXX) # use clang++ for compiling c modules as well, because, syms.resolver
	CXXFLAGS:=-std=c++1z -Wall  -I./Switch/ -DSWITCH_MIN -Wno-unknown-pragmas -Wno-undefined-inline -Ofast
	CFLAGS:=-xc++ -Ofast
	LDFLAGS_TLS:=-ldl -lssl -lcrypto
	LDFLAGS_SANITY:=
	LDFLAGS:=
	EOBJS:=Switch/text.o Switch/ext/ext_xxhash.o Switch/base64.o Switch/data.o Switch/switch_security.o
	MYSQL_LIBS:=-lmysqlclient
	CLEANUP_EXTRA:=rm -f $(EOBJS)
	# We are only going to build service for now, not the C++ client, which depends on all kind of various Switch modules
	# Will be enabled later though
	TARGETS:=service
endif

all: $(TARGETS)

service: $(EOBJS) service.o
	$(CC) service.o $(EOBJS) -o kms $(LDFLAGS_SANITY) $(LDFLAGS) -pthread $(LDFLAGS_TLS)  $(MYSQL_LIBS) sss/*.o

client: kms_client.o
	ar rcs libkms.a kms_client.o

clean:
	rm -f *.o kms
	$(CLEANUP_EXTRA)

.o: .cpp

.PHONY: clean
