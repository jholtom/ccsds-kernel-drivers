# Makefile for spp test-suite
# Author: Jacob Willis

CFLAGS		:= -Os -mcpu=cortex-m3 -mthumb -I/home/ecestudent/linux-cortexm-1.14.3/A2F/root/usr/include/
LDFLAGS		:= -mcpu=cortex-m3 -mthumb
CC		= $(CROSS_COMPILE_APPS)gcc

sender: sender.o
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

receiver: receiver.o
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
			rm -f *.o *~
