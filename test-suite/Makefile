# Makefile for sppconfig (first attempt)
# Author: Jacob Willis

CFLAGS		:= -Os -mcpu=cortex-m3 -mthumb -I/home/ecestudent/linux-cortexm-1.14.3/A2F/root/usr/include/
LDFLAGS		:= -mcpu=cortex-m3 -mthumb -l/home/ecestudent/linux-cortexm-1.14.3/A2F/root/usr/include/
CC		= $(CROSS_COMPILE_APPS)gcc

main: main.o
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
			rm -f *.o *~
