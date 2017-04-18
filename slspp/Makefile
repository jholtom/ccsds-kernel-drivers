#
# Makefile for the SLSSP network device drivers.
#

#obj-$(CONFIG_SLSPP) += slssp.o
# Use above if compiling in kernel tree

obj-m += slssp.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
