
//===================================打印网卡信息&选择网卡并抓取ICMP数据包=================================

#include <pcap.h>
#include <Windows.h>
#include <cstdlib>
#include <cstdio>
#include <WS2tcpip.h>

#define MAX_PRINT 80
#define MAX_LINE 16

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls() {
    CHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    strcat_s(npcap_dir, 512, "\\Npcap");
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

/**
* IPv4 结构
*/
typedef struct {
#define IPH_GET_VER(v) (((v) >> 4) & 0x0F)
#define IPH_GET_LEN(v) (((v) & 0x0F) << 2)
    uint8_t version_len;

    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;

#define IP_OFFMASK 0x1fff
    uint16_t frag_off;
    uint8_t ttl;

#define IP_PROTO_UDP  17  /* UDP protocol */
#define IP_PROTO_TCP   6  /* TCP protocol */
#define IP_PROTO_ICMP  1  /* ICMP protocol */
#define IP_PROTO_IGMP  2  /* IGMP protocol */
    uint8_t protocol;

    uint16_t check_sum;
    uint32_t saddr;
    uint32_t daddr;
    /* The options start here. */
} IPHDR;

/**
* ICMP 头结构
*/
typedef struct {
    IPHDR ip_hdr;
    uint8_t type;
    uint8_t code;
    uint16_t check_sum;
    /* data start here. */
} ICMPHDR;


void usage();

void packet_handler(unsigned char *param, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    IPHDR *IpHdr = (IPHDR *) (packet + 14);
    //    printf("pkt len %d,%d\n",pkthdr->len,IpHdr->protocol);
    // 只处理ICMP
    if (IpHdr->protocol != IP_PROTO_ICMP) {
        return;
    }

    // 输出源目的地址
    struct in_addr s;
    struct in_addr d;
    s.s_addr = IpHdr->saddr;
    d.s_addr = IpHdr->daddr;
    char sipstr[30] = {0};
    char dipstr[30] = {0};
    InetNtop(AF_INET, &s.s_addr, sipstr, sizeof(sipstr));
    InetNtop(AF_INET, &d.s_addr, dipstr, sizeof(dipstr));
    printf("icmp %s --> %s\n", sipstr, dipstr);
}


int main(int argc, char **argv) {
    pcap_t *fp = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *netname = NULL;

#ifdef _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif

    if (argc == 1) {
        usage();
        return -1;
    }

    netname = argv[1];

    // open a capture from the network
    if (netname != NULL) {
        if ((fp = pcap_open_live(netname, // name of the device
                                 65536, // portion of the packet to capture.
                                 // 65536 grants that the whole packet will be captured on all the MACs.
                                 1, // promiscuous mode (nonzero means promiscuous)
                                 1000, // read timeout
                                 errbuf // error buffer
             )) == NULL) {
            fprintf(stderr, "\nUnable to open the adapter.\n");
            return -2;
        }

        pcap_loop(fp, 0, packet_handler, NULL);
    } else usage();


    return 0;
}


void usage() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *d;
    int i = 0;
    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    printf("exec <netname>\n");
    exit(0);
}
