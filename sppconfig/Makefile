# Makefile for sppconfig (first attempt)
# Author: Jacob Willis

CFLAGS		:= -O0 -g -mcpu=cortex-m3 -mthumb -I/home/ecestudent/linux-cortexm-1.14.3/A2F/root/usr/include/
OUTPATH := -o ~/linux-cortexm-1.14.3/projects/skeleton/sppconfig.out
LDFLAGS		:= -mcpu=cortex-m3 -mthumb
CC		= $(CROSS_COMPILE_APPS)gcc

DEPS = config.h  interface.h  intl.h  ipx.h  net-support.h
DEPS += pathnames.h  proc.h  sockets.h  util.h  version.h

ODIR=obj
_OBJ = af.o  getroute.o  hippi.o  hw.o  interface.o  nstrcmp.o loopback.o
_OBJ += proc.o  sockets.o  util.o unix.o spplib.o slip.o sppconfig.o

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

sppconfig: $(OBJ)
	$(CC) $(OUTPATH) $^ $(CFLAGS)

clean:
			rm -f $(ODIR)/*.o *~
