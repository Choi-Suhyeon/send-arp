#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <pcap/pcap.h>

// TODO :
// 1) modify ARP header(hardwareSize: 6, protocolSize: 4)
// 2) solve segmentation fault. goto '// DEBUG'

typedef struct ifreq ifreq_t;
typedef struct pcap_pkthdr pcap_pkthdr_t;

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
    uint8_t  senderMacAddr[6];
    uint32_t senderIpAddr;
    uint8_t  targetMacAddr[6];
    uint32_t targetIpAddr;
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
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sd, SIOCGIFADDR, &ifr);
    close(sd);

    return ((sockaddr_in_t *)&ifr.ifr_addr)->sin_addr;
}

uint32_t parseIPv4Addr(int8_t * ipAddrStr) {
    int8_t result[4] = { 0 };

    sscanf(ipAddrStr, "%u.%u.%u.%u", result + 0, result + 1, result + 2, result + 3);

    return *(uint32_t *)result;
}

void macStrToHex_innerFn(int8_t * str, uint8_t ** out) {
    // TODO: get length of mac address as parameter
    // and parse string with function strtok
    // stop when parsing is end or over the length.
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

uint32_t checkInterfaceName(int8_t * interfaceName) {
    int8_t * ptr = interfaceName;

    while (*ptr) {
        if (NULL 
            || *ptr == '.' 
            || *ptr == '/' 
            || *ptr == '\\') return 0;
        
        ++ptr;
    }

    return 1;
}

int main(int argc, char ** argv) {
    if (argc < 4) {
        printf("Error: At least four command-line arguments are required.\n"
               "syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n"
               "sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");

        return 1;
    }

    if (!checkInterfaceName(argv[1])) {
        printf("Error: Please refrain from entering abnormal entries.\n");

        return 1;
    }

    // Get atacker's mac & ip address
    uint8_t * attackerMacAddr;

    uint8_t * senderMacAddr = calloc(6, 1);
    
    uint32_t attackerIPAddr = getSelfIPv4Addr(argv[1]);
    
    getSelfMacAddr(argv[1], &attackerMacAddr);

    // Set buffer packet
    MACheader macHdr = { .etherType = htons(0x0806) };
    ARPheader arpHdr = { 
        .hardwareType = htons(0x0001), 
        .protocolType = htons(0x0800),
        .opcode       = htons(0x0001),
        .protocolSize = 4,
        .hardwareSize = 6,
        .senderIpAddr = attackerIPAddr,
        .targetIpAddr = parseIPv4Addr(argv[2]),
    };

    memset(&macHdr.destMacAddr, 0xFF, 6);
    memset(&arpHdr.targetMacAddr, 0x00, 6);
    memcpy(&macHdr.srcMacAddr, attackerMacAddr, 6);
    memcpy(&arpHdr.senderMacAddr, attackerMacAddr, 6);

    // Send ARP packet to get sender's mac address
    int8_t        errBuf[PCAP_ERRBUF_SIZE];
    uint8_t       * packet;
    pcap_pkthdr_t header;

    int32_t bufferSize  = sizeof(MACheader) + sizeof(ARPheader);
    pcap_t  * pcap      = pcap_open_live(argv[1], 0, 0, 0, errBuf);
    uint8_t * buffer    = calloc(bufferSize, sizeof(uint8_t)),
            * bufOffset = buffer;

    memcpy(bufOffset += 0, &macHdr, sizeof macHdr);
    memcpy(bufOffset += sizeof macHdr, &arpHdr, sizeof arpHdr);
    
    // pcap_sendpacket(pcap, buffer, bufferSize);
    // pcap_close(pcap);
    /*
    printf("attackerIPAddr  : %X\nattackerMacAddr : ", attackerIPAddr);

    for (int i = 0; i < 6; i++) {
        printf("%02X ", attackerMacAddr[i]);
    }
    printf("\nsenderMacAddress : ");
    for (int i = 0; i < 6; i++) {
        printf("%02X ", senderMacAddr[i]);
    }
    puts("");

    puts("[sned arp packet] : ");
    for (int i = 0; i < bufferSize; i++) {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0) puts("");
    }
    puts("");*/

    // reply packet
    pcap_t * pcapReply = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errBuf);

    while (1) {
        const uint8_t * packet;
        pcap_pkthdr_t * header;

        pcap_sendpacket(pcap, buffer, bufferSize);

        int32_t res = pcap_next_ex(pcapReply, &header, &packet);

        if (!res) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

            break;
        }

        puts("[capture packet] - breif");
        printf("etherType : %04X\n", ntohs(((MACheader *)packet)->etherType));
        if (ntohs(((MACheader *)packet)->etherType) == 0x0806) {
            printf("opcode : %04X\n", ntohs(((ARPheader *)(packet + sizeof(MACheader)))->opcode));
            printf("senderIP : %08X\n", ntohl(((ARPheader *)(packet + sizeof(MACheader)))->senderIpAddr));
            printf("senderIP : %08X\n", parseIPv4Addr(argv[2]));
            puts("[capture packet]");
            for (int i = 0; i < header->caplen; i++) {
                printf("%02X ", packet[i]);
                if ((i + 1) % 16 == 0) puts("");
            }
            puts("");
        }

        if (!NULL
            && ntohs(((MACheader *)packet)->etherType) == 0x0806 
            && ntohs(((ARPheader *)(packet + sizeof(MACheader)))->opcode) == 0x0002
            && ((ARPheader *)(packet + sizeof(MACheader)))->senderIpAddr == parseIPv4Addr(argv[2]))
        {
            memcpy(senderMacAddr, ((ARPheader *)(packet + sizeof macHdr))->senderMacAddr, 6);
            
            break;
        }
    }

    pcap_close(pcap);

    // checking

    free(attackerMacAddr);
    free(senderMacAddr);
    free(buffer);

    return 0;
}
