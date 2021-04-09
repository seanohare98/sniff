#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <pcap.h>


void udp_attack(uint16_t port, char* ip) {
    int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("connection error: %s (Errno:%d)\n", strerror(errno), errno);
        close(sd);
        return;
    }

    int buflen = 1000;
    char* buf = (char*)calloc(buflen, sizeof(char));
    memset(buf, 47, buflen);
    int sendlen = send(sd, buf, buflen, 0);
    if (sendlen < 0) {
        printf("%s\n", strerror(errno));
    }
    else
    {
        printf("attack %s:%d, len:%d/%d\n", ip, port, sendlen, buflen);
    }

    close(sd);
}

void udp_heavy_hitter_attack(uint16_t port, char* ip) {
    int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("connection error: %s (Errno:%d)\n", strerror(errno), errno);
        close(sd);
        return;
    }

    int onemb = 1000000;
    int total_length = onemb * 50;
    int remaining_length = total_length;

    while (remaining_length > 0)
    {
        int buflen = 1000;
        char* buf = (char*)calloc(buflen, sizeof(char));
        memset(buf, 47, buflen);
        int sendlen = send(sd, buf, buflen, 0);
        if (sendlen < 0) {
            printf("%s\n", strerror(errno));
        }
        else
        {
            // printf("attack %s:%d, len:%d/%d, ", ip, port, sendlen, buflen);
            remaining_length -= sendlen;
            // printf("sent %d/%d\n", total_length - remaining_length, total_length);
        }
    }
    
    printf("attack %s:%d, len:%d/%d\n", ip, port, total_length - remaining_length, total_length);

    close(sd);
}

int main(int argc, char const *argv[])
{
    char vm1[10] = "10.0.12.1";

    printf("===== vertical portscan =====\n");
    for (uint16_t port = 1000; port < 1050; port++)
    {
        udp_attack(port, vm1);
    }

    printf("===== horizontal portscan =====\n");
    for (int i = 1; i < 50; i++)
    {
        char ip[11];
        sprintf(ip, "10.0.12.%02d", i);
        udp_attack(3000, ip);
    }

    printf("===== heavy hitter =====\n");
    udp_heavy_hitter_attack(2000, vm1);

    for (int i = 0; i < 60; i++)
    {
        printf("==== waiting for %d seconds so an epoch passes ====\n", 60-i);
        sleep(1); 
    }
    udp_attack(1000, vm1);
    
    return 0;
}
