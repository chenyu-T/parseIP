#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <string>
#include <pcap.h>

using namespace std;

// 解码数据链路数据包 数据链路层为二层,解码时只需要封装一层ether以太网数据包头即可.
#define hcons(A) (((WORD)(A)&0xFF00)>>8) | (((WORD)(A)&0x00FF)<<8)

void PrintEtherHeader(const u_char * packetData)
{
    typedef struct ether_header
    {
        u_char ether_dhost[6];    // 目标地址
        u_char ether_shost[6];    // 源地址
        u_short ether_type;       // 以太网类型
    } ether_header;

    struct ether_header * eth_protocol;
    eth_protocol = (struct ether_header *)packetData;

    u_short ether_type = ntohs(eth_protocol->ether_type);  // 以太网类型
    u_char *ether_src = eth_protocol->ether_shost;         // 以太网原始MAC地址
    u_char *ether_dst = eth_protocol->ether_dhost;         // 以太网目标MAC地址

    printf("类型: 0x%x \t", ether_type);
    printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
      ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
    printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
      ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

// 解码IP数据包，IP层在数据链路层的下面, 解码时需要+14偏移值, 跳过数据链路层。
void PrintIPHeader(const u_char * packetData)
{
    typedef struct ip_header
    {
        char version : 4;
        char headerlength : 4;
        char cTOS;
        unsigned short totla_length;
        unsigned short identification;
        unsigned short flags_offset;
        char time_to_live;
        char Protocol;
        unsigned short check_sum;
        unsigned int SrcAddr;
        unsigned int DstAddr;
    }ip_header;

    struct ip_header *ip_protocol;

    // +14 跳过数据链路层
    ip_protocol = (struct ip_header *)(packetData + 14);
    SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

    u_short check_sum = ntohs(ip_protocol->check_sum);
    int ttl = ip_protocol->time_to_live;
    int proto = ip_protocol->Protocol;

    Src_Addr.sin_addr.s_addr = ip_protocol->SrcAddr;
    Dst_Addr.sin_addr.s_addr = ip_protocol->DstAddr;

    printf("源地址: %15s --> ", inet_ntoa(Src_Addr.sin_addr));
    printf("目标地址: %15s --> ", inet_ntoa(Dst_Addr.sin_addr));

    printf("校验和: %5X --> TTL: %4d --> 协议类型: ", check_sum, ttl);
    switch (ip_protocol->Protocol)
    {
        case 1: printf("ICMP \n"); break;
        case 2: printf("IGMP \n"); break;
        case 6: printf("TCP \n");  break;
        case 17: printf("UDP \n"); break;
        case 89: printf("OSPF \n"); break;
        default: printf("None \n"); break;
    }
}

// 解码TCP数据包，需要先加14跳过数据链路层, 然后再加20跳过IP层。
void PrintTCPHeader(const unsigned char * packetData)
{
    typedef struct tcp_header
    {
        short SourPort;                 // 源端口号16bit
        short DestPort;                 // 目的端口号16bit
        unsigned int SequNum;           // 序列号32bit
        unsigned int AcknowledgeNum;    // 确认号32bit
        unsigned char reserved : 4, offset : 4; // 预留偏移

        unsigned char  flags;               // 标志

        short WindowSize;               // 窗口大小16bit
        short CheckSum;                 // 检验和16bit
        short surgentPointer;           // 紧急数据偏移量16bit
    }tcp_header;

    struct tcp_header *tcp_protocol;
    // +14 跳过数据链路层 +20 跳过IP层
    tcp_protocol = (struct tcp_header *)(packetData + 14 + 20);

    u_short sport = ntohs(tcp_protocol->SourPort);
    u_short dport = ntohs(tcp_protocol->DestPort);
    int window = tcp_protocol->WindowSize;
    int flags = tcp_protocol->flags;

    printf("源端口: %6d --> 目标端口: %6d --> 窗口大小: %7d --> 标志: (%d)",
      sport, dport, window, flags);

    if (flags & 0x08) printf("PSH 数据传输\n");
    else if (flags & 0x10) printf("ACK 响应\n");
    else if (flags & 0x02) printf("SYN 建立连接\n");
    else if (flags & 0x20) printf("URG \n");
    else if (flags & 0x01) printf("FIN 关闭连接\n");
    else if (flags & 0x04) printf("RST 连接重置\n");
    else printf("None 未知\n");
}

// UDP层与TCP层如出一辙,仅仅只是在结构体的定义解包是有少许的不同而已.
void PrintUDPHeader(const unsigned char * packetData)
{
    typedef struct udp_header
    {
        uint32_t sport;   // 源端口
        uint32_t dport;   // 目标端口
        uint8_t zero;     // 保留位
        uint8_t proto;    // 协议标识
        uint16_t datalen; // UDP数据长度
    }udp_header;

    struct udp_header *udp_protocol;
    // +14 跳过数据链路层 +20 跳过IP层
    udp_protocol = (struct udp_header *)(packetData + 14 + 20);

    u_short sport = ntohs(udp_protocol->sport);
    u_short dport = ntohs(udp_protocol->dport);
    u_short datalen = ntohs(udp_protocol->datalen);

    printf("源端口: %5d --> 目标端口: %5d --> 大小: %5d \n", sport, dport, datalen);
}

// 解码ICMP数据包，在解包是需要同样需要跳过数据链路层和IP层, 然后再根据ICMP类型号解析, 常用的类型号为`type 8`它代表着发送和接收数据包的时间戳。
void PrintICMPHeader(const unsigned char * packetData)
{
    typedef struct icmp_header {
        uint8_t type;        // ICMP类型
        uint8_t code;        // 代码
        uint16_t checksum;   // 校验和
        uint16_t identification; // 标识
        uint16_t sequence;       // 序列号
        uint32_t init_time;      // 发起时间戳
        uint16_t recv_time;      // 接受时间戳
        uint16_t send_time;      // 传输时间戳
    }icmp_header;

    struct icmp_header *icmp_protocol;

    // +14 跳过数据链路层 +20 跳过IP层
    icmp_protocol = (struct icmp_header *)(packetData + 14 + 20);

    int type = icmp_protocol->type;
    int init_time = icmp_protocol->init_time;
    int send_time = icmp_protocol->send_time;
    int recv_time = icmp_protocol->recv_time;
    if (type == 8)
    {
        printf("发起时间戳: %d --> 传输时间戳: %d --> 接收时间戳: %d 方向: ",
          init_time, send_time, recv_time);

        switch (type)
        {
            case 0: printf("回显应答报文 \n"); break;
            case 8: printf("回显请求报文 \n"); break;
            default:break;
        }
    }
}

// 解码HTTP数据包，需要跳过数据链路层, IP层以及TCP层, 最后即可得到HTTP数据包协议头。
void PrintHttpHeader(const unsigned char * packetData)
{
    typedef struct tcp_port
    {
        unsigned short sport;
        unsigned short dport;
    }tcp_port;

    typedef struct http_header
    {
        char url[512];
    }http_header;

    struct tcp_port *tcp_protocol;
    struct http_header *http_protocol;

    tcp_protocol = (struct tcp_port *)(packetData + 14 + 20);
    int tcp_sport = ntohs(tcp_protocol->sport);
    int tcp_dport = ntohs(tcp_protocol->dport);

    if (tcp_sport == 80 || tcp_dport == 80)
    {
        // +14 跳过MAC层 +20 跳过IP层 +20 跳过TCP层
        http_protocol = (struct http_header *)(packetData + 14 + 20 + 20);
        printf("%s \n", http_protocol->url);
    }
}

// 解码ARP数据包
void PrintArpHeader(const unsigned char * packetData)
{
    typedef struct arp_header
    {
        uint16_t arp_hardware_type;
        uint16_t arp_protocol_type;
        uint8_t arp_hardware_length;
        uint8_t arp_protocol_length;
        uint16_t arp_operation_code;
        uint8_t arp_source_ethernet_address[6];
        uint8_t arp_source_ip_address[4];
        uint8_t arp_destination_ethernet_address[6];
        uint8_t arp_destination_ip_address[4];
    }arp_header;

    struct arp_header *arp_protocol;

    arp_protocol = (struct arp_header *)(packetData + 14);

    u_short hardware_type = ntohs(arp_protocol->arp_hardware_type);
    u_short protocol_type = ntohs(arp_protocol->arp_protocol_type);
    int arp_hardware_length = arp_protocol->arp_hardware_length;
    int arp_protocol_length = arp_protocol->arp_protocol_length;
    u_short operation_code = ntohs(arp_protocol->arp_operation_code);

    // 判读是否为ARP请求包
    if (arp_hardware_length == 6 && arp_protocol_length == 4)
    {
        printf("原MAC地址: ");
        for (int x = 0; x < 6; x++)
            printf("%x:", arp_protocol->arp_source_ethernet_address[x]);
        printf(" --> ");

        printf("目标MAC地址: ");
        for (int x = 0; x < 6; x++)
            printf("%x:", arp_protocol->arp_destination_ethernet_address[x]);
        printf(" --> ");

        switch (operation_code)
        {
            case 1: printf("ARP 请求 \n"); break;
            case 2: printf("ARP 应答 \n"); break;
            case 3: printf("RARP 请求 \n"); break;
            case 4: printf("RARP 应答 \n"); break;
            default: break;
        }
    }
}

// 选择网卡并根据不同参数解析数据包
void MonitorAdapter(int nChoose, char *Type)
{
    pcap_if_t *adapters;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1)
    {
        // 找到指定的网卡
        for (int x = 0; x < nChoose - 1; ++x)
            adapters = adapters->next;

        // PCAP_OPENFLAG_PROMISCUOUS = 网卡设置为混杂模式
        // 1000 => 1000毫秒如果读不到数据直接返回超时
        pcap_t * handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0);

        if (adapters == NULL)
            return;

        // printf("开始侦听: % \n", adapters->description);
        pcap_pkthdr *Packet_Header;    // 数据包头
        const u_char * Packet_Data;    // 数据本身
        int retValue;
        while ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)
        {
            if (retValue == 0)
                continue;

            // printf("侦听长度: %d \n", Packet_Header->len);
            if (strcmp(Type, "ether") == 0)
            {
                PrintEtherHeader(Packet_Data);
            }
            if (strcmp(Type, "ip") == 0)
            {
                PrintIPHeader(Packet_Data);
            }
            if (strcmp(Type, "tcp") == 0)
            {
                PrintTCPHeader(Packet_Data);
            }
            if (strcmp(Type, "udp") == 0)
            {
                PrintUDPHeader(Packet_Data);
            }
            if (strcmp(Type, "icmp") == 0)
            {
                PrintICMPHeader(Packet_Data);
            }
            if (strcmp(Type, "http") == 0)
            {
                PrintHttpHeader(Packet_Data);
            }
            if (strcmp(Type, "arp") == 0)
            {
                PrintArpHeader(Packet_Data);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    MonitorAdapter(7,"ether");
    system("pause");
    return 0;
}