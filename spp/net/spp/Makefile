#
# Makefile for SPP in Linux
#

obj-$(CONFIG_SPP) += spp.o

spp-y := af_spp.o spp_addr.o spp_in.o spp_loopback.o spp_methods.o spp_out.o spp_proc.o spp_timer.o
spp-$(CONFIG_SYSCTL) += sysctl_net_spp.o
