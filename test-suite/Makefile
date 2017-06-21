# Makefile for sppconfig (first attempt)
# Author: Jacob Willis

CFLAGS		:= -Os -mcpu=cortex-m3 -mthumb -I/home/jacob/M2S/linux-cortexm-1.14.3/A2F/root/usr/include/
LDFLAGS		:= -mcpu=cortex-m3 -mthumb
CC		= $(CROSS_COMPILE_APPS)gcc

main: main.o
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
			rm -f *.o *~
