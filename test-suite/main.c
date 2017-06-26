#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netspp/spp.h>

int main() {
    int fd;
    struct sockaddr_spp myaddr;
    struct sockaddr_spp servaddr;

    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sspp_family = AF_SPP;
    spp_address spp_myaddr = { 2001 };
    myaddr.sspp_addr = spp_myaddr;

    memset((char *)&servaddr, 0, sizeof(servaddr));
    servaddr.sspp_family = AF_SPP;
    spp_address spp_servaddr = { 2002 };
    myaddr.sspp_addr = spp_servaddr;

    if ((fd = socket(AF_SPP, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        perror("bind failed");
        return -2;
    }

    char *my_message = "this is a test message";
    if (sendto(fd, my_message, strlen(my_message), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto failed");
        return -3;
    }
  //  int rc;
  //  unsigned char recvdata[BUFSIZE];
  //  rc = recvfrom(fd, recvdata, BUFSIZE, (struct sockaddr *)&servaddr, sizeof(servaddr));
    /* could also use recv() but you need to connect() first */
        return 0; /* Somehow this thing works */
}
