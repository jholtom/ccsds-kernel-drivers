#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {

    struct sockaddr_spp myaddr;
    struct sockaddr_spp servaddr;

    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sspp_family = AF_SPP;
    myaddr.sspp_addr = {2001};

    memset((char *)&servaddr, 0, sizeof(servaddr));
    servaddr.sspp_family = AF_SPP;
    servaddr.sspp_addr = {2002};

    if ((fd = socket(AF_SPP, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        perror("bind failed");
        return -2;
    }

    char *my_messsage = "this is a test message";
    if (sendto(fd, my_message, strlen(my_message), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto failed");
        return 0;
    }
}
