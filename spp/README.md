# SPP
- Space Packet Protocol Network Layer - INET driver - For Linux 2.6.33

# To add to your kernel
- Copy net/ and include/ into the root of your linux/ source tree
- Adjust net/Kconfig to have `source "net/spp/Kconfig"`
- Adjust net/Makefile to have `obj-$(CONFIG_SPP) += spp/`

# TODO
- Acquire AF_SPP assignment in <linux/socket.h>
    - In the meantime, you can just go add your own, I've been using this snippet
    ```
    #define AF_SPP 37 /* Space Packet Protocol sockets */
    ...
    #define PF_SPP AF_SPP
    ```
    - I also adjust AF_MAX to be 38.
- Acquire ETH_P_SPP in <linux/if_ether.h>
    - In the meantime, you can just go add your own again, I've been using this snippet
    ```
    #define ETH_P_SPP 0x0807 /* CCSDS SPP */
    ```
