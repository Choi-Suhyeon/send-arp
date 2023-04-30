#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

typedef struct ifreq ifreq_t;

#pragma pack(push, 1)
typedef struct {
    int16_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    int8_t   sin_zero[8];
} sockaddr_in_t;

typedef struct {
    uint8_t  destMacAddr[6],
             srcMacAddr[6];
    uint16_t etherType;
} MACheader;

typedef struct {
    uint16_t hardwareType,
             protocolType;
    uint8_t  hardwareSize,
             protocolSize;
    uint16_t opcode;
} ARPheader;
#pragma pack(pop)

int32_t readWholeTextData(int8_t * fileName, int8_t ** pBuffer) {
    FILE * fp;

    if (!(fp = fopen(fileName, "rt"))) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);

    uint32_t length = ftell(fp);

    if (!(*pBuffer = calloc(length + 1, 1))) {
        fclose(fp);

        return 0;
    }

    fseek(fp, 0, SEEK_SET);
    fread(*pBuffer, length, 1, fp);
    fclose(fp);

    return 1;
}

int32_t readTextData(int8_t * fileName, int8_t ** pBuffer, uint32_t length) {
    FILE * fp;

    if (!(fp = fopen(fileName, "rt"))) {
        return 0;
    }

    if (!(*pBuffer = calloc(length + 1, 1))) {
        fclose(fp);

        return 0;
    }

    fread(*pBuffer, length, 1, fp);
    fclose(fp);

    return 1;
}

uint32_t getSelfIPv4Addr(int8_t * interface) {
    int     sd  = socket(AF_INET, SOCK_STREAM, 0);
    ifreq_t ifr = { .ifr_addr.sa_family = AF_INET };
    
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    ioctl(sd, SIOCGIFADDR, &ifr);
    close(sd);

    return ((sockaddr_in_t *)&ifr.ifr_addr)->sin_addr;
}

void macStrToHex_innerFn(int8_t * str, uint8_t ** out) {
    uint32_t numOfColon = 0;
    
    for (uint32_t i = 0; str[i]; i++) numOfColon += !!(str[i] == ':');
    
    uint32_t outLen = (strlen(str) - numOfColon) >> 1;
    
    *out = calloc(outLen, sizeof(uint8_t));
    
    for (uint32_t i = 0, strI = 0; i < outLen; i++, strI += 3) {
        int8_t * endPtr = str + strI + 2;

        (*out)[i] = (uint8_t)strtoul(str + strI, (char **)&endPtr, 16);
    }
}

uint32_t getSelfMacAddr(int8_t * interface, uint8_t ** out) {
    int8_t locationOfMacAddr[45] = { 0 };
    int8_t * tempMacAddr;

    sprintf(locationOfMacAddr, "/sys/class/net/%s/address", interface);
    
    if (!readWholeTextData(locationOfMacAddr, &tempMacAddr)) {
        return 0;
    }

    macStrToHex_innerFn(tempMacAddr, out);
    free(tempMacAddr);
            
    return 1;
}

int main(int argc, char ** argv) {
    if (argc < 4) {
        printf("Error: At least four command-line arguments are required.\n"
               "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n"
               "sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");

        return 1;
    }
    
    uint8_t * attackerMacAddr;
    
    uint32_t attackerIPAddr = getSelfIPv4Addr(argv[1]);
    
    getSelfMacAddr(argv[1], &attackerMacAddr);
    
    // checking

    printf("attackerIPAddr  : %X\nattackerMacAddr : ", attackerIPAddr);

    for (int i = 0; i < 6; i++) {
        printf("%02X", attackerMacAddr[i]);
    }
    puts(""); 

    free(attackerMacAddr);
     

    return 0;
}
