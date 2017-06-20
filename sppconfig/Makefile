# Makefile for sppconfig (first attempt)
# Author: Jacob Willis

CC=gcc
CFLAGS= -Wall
DEPS = config.h  interface.h  intl.h  ipx.h  net-support.h
DEPS += pathnames.h  proc.h  sockets.h  util.h  version.h
OBJ = af.o  getroute.o  hippi.o  hw.o  interface.o  nstrcmp.o loopback.o
OBJ += proc.o  sockets.o  util.o unix.o slip.o sppconfig.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sppconfig: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
			rm -f *.o
