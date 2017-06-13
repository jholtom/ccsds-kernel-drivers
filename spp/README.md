# SPP
- Space Packet Protocol Network Layer - INET driver - For Linux 2.6.33

# To add to your kernel
- Copy net/ and include/ into the root of your linux/ source tree
- Adjust net/Kconfig to have `source "net/spp/Kconfig"`
- Adjust net/Makefile to have `obj-$(CONFIG_SPP) += spp/`
