# Makefile for sppconfig (first attempt)
# Author: Jacob Willis

CFLAGS		:= -Os -mcpu=cortex-m3 -mthumb
LDFLAGS		:= -mcpu=cortex-m3 -mthumb
CC		= $(CROSS_COMPILE_APPS)gcc

DEPS = config.h  interface.h  intl.h  ipx.h  net-support.h
DEPS += pathnames.h  proc.h  sockets.h  util.h  version.h

ODIR=obj
_OBJ = af.o  getroute.o  hippi.o  hw.o  interface.o  nstrcmp.o loopback.o
_OBJ += proc.o  sockets.o  util.o unix.o slip.o sppconfig.o

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))



$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

sppconfig: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
			rm -f $(ODIR)/*.o *~
