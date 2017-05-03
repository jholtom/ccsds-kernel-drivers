#
# Makefile for the SDLP network device drivers.
#

#obj-$(CONFIG_SDLP) += sdlp.o
# Use above if compiling in kernel tree

obj-m += sdlp.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
