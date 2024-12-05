#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

// 定义以太网头部
struct ether_header {
    uint8_t ether_dhost[6]; // 目标MAC地址
    uint8_t ether_shost[6]; // 源MAC地址
    uint16_t ether_type;    // 以太网类型
};

// 定义IP头部
struct ip_header {
    uint8_t ip_header_len : 4; // IP头部长度
    uint8_t ip_version : 4;    // IP版本
    uint8_t ip_tos;            // 服务类型
    uint16_t ip_total_length;  // 总长度
    uint16_t ip_id;            // 标识符
    uint16_t ip_frag_offset;   // 分片偏移
    uint8_t ip_ttl;            // 生存时间
    uint8_t ip_protocol;       // 协议
    uint16_t ip_checksum;      // 校验和
    uint32_t ip_src;           // 源IP地址
    uint32_t ip_dst;           // 目标IP地址
};

// 定义以太网类型
#define ETHERTYPE_IP 0x0800 // IP 协议类型

// CIDR 地址解析
void parse_cidr(const char* cidr, uint32_t* network, uint32_t* mask) {
    char ip[INET_ADDRSTRLEN];
    int prefix_len;

    // 分割IP地址和前缀长度
    sscanf(cidr, "%[^/]/%d", ip, &prefix_len);

    // 转换IP地址为整数
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    *network = ntohl(addr.s_addr);

    // 生成子网掩码
    *mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
}

// 检查IP是否属于给定子网
int is_ip_in_subnet(uint32_t ip, uint32_t network, uint32_t mask) {
    return (ip & mask) == (network & mask);
}

// 打印IP地址
void print_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    printf("%s\n", inet_ntoa(addr));
}

// 处理数据包
void process_packet(const uint8_t* packet, uint32_t network, uint32_t mask) {
    struct ether_header* eth_hdr = (struct ether_header*)packet;

    // 仅处理IP包
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        struct ip_header* ip_hdr = (struct ip_header*)(packet + sizeof(struct ether_header));

        // 获取源IP地址
        uint32_t src_ip = ntohl(ip_hdr->ip_src);

        // 检查源IP是否属于子网
        if (is_ip_in_subnet(src_ip, network, mask)) {
            printf("Device IP in subnet: ");
            print_ip(src_ip);
        }
    }
}

int main() {
    // 定义CIDR地址块，不再通过命令行传参 169.254.189.90
    std::string cidr = "";  // 这里定义一个具体的CIDR地址块

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* dev_list;
    pcap_t* handle;

    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }

    // 解析CIDR地址块
    uint32_t network, mask;
    parse_cidr(cidr.c_str(), &network, &mask);

    // 获取所有设备
    if (pcap_findalldevs(&dev_list, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        WSACleanup();
        return -1;
    }

    // 选择第一个网络接口
    pcap_if_t* dev = dev_list;
    if (dev == nullptr) {
        fprintf(stderr, "No devices found\n");
        WSACleanup();
        return -1;
    }

    // 打开网络设备
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Error opening device %s: %s\n", dev->name, errbuf);
        WSACleanup();
        return -1;
    }

    printf("Listening for packets on device: %s\n", dev->name);

    // 捕获数据包并处理
    while (true) {
        struct pcap_pkthdr header;
        const uint8_t* packet = pcap_next(handle, &header);
        if (packet == nullptr) {
            continue;
        }

        // 处理IP数据包
        process_packet(packet, network, mask);
    }

    // 清理
    pcap_close(handle);
    WSACleanup();

    return 0;
}
