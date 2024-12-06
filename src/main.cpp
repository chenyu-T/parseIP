#include <cstdint>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <ws2tcpip.h>

struct in_addr addr;
// 将 IP 地址字符串转换为 32 位整数
uint32_t ip2Int(const std::string ip) {
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        std::cerr << "Invalid IP address: " << ip << std::endl;
        return 0;
    }
    // 转换为主机字节序
    return ntohl(addr.s_addr);
}

// 检查 IP 是否属于 CIDR 地址块
bool ip_in_cidr(const std::string ip, const std::string cidr) {
    size_t pos = cidr.find('/');
    std::string cidr_ip_str = cidr.substr(0, pos);
    int netmask_len = std::stoi(cidr.substr(pos + 1));

    // 将IP地址转换为32位整数
    uint32_t ip_value = ip2Int(ip);
    // 将CIDR网络地址转换为32位整数
    uint32_t cidr_ip_value = ip2Int(cidr_ip_str);

    // 计算子网掩码（CIDR子网长度）
    uint32_t ip_mask = (0xFFFFFFFF << (32 - netmask_len)) & 0xFFFFFFFF;

    // 检查IP是否在CIDR地址块内
    return (ip_value & ip_mask) == (cidr_ip_value & ip_mask);
}

std::string GetIPv4(std::string cidr) {
    //PIP_ADAPTER_INFO结构体指针存储本机网卡信息
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //得到结构体大小,用于GetAdaptersInfo参数
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        //如果函数返回的是ERROR_BUFFER_OVERFLOW
        //则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
        //这也是说明为什么stSize既是一个输入量也是一个输出量
        //释放原来的内存空间
        delete pIpAdapterInfo;
        //重新申请内存空间用来存储所有网卡信息
        pIpAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[stSize];
        //再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }
    if (ERROR_SUCCESS == nRel) {
        //输出网卡信息
        //可能有多网卡,因此通过循环去判断
        std::string ip;
        while (pIpAdapterInfo) {
            IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
            do {
                ip = pIpAddrString->IpAddress.String;
                if(ip_in_cidr(ip,cidr)) {
                    return ip;
                }
                pIpAddrString = pIpAddrString->Next;
            } while (pIpAddrString);
            pIpAdapterInfo = pIpAdapterInfo->Next;
        }
    }
    //释放内存空间
    if (pIpAdapterInfo) {
        delete pIpAdapterInfo;
    }
    return "";
}

int main() {
    //抓取本机所有IP，筛选cidr范围内的目标
    std::string ip= GetIPv4("192.168.1.43/24");
    if(ip!="") {
        std::cout<<ip<<std::endl;
    }
    else {
        std::cout<<"error: can not get ip."<<std::endl;
    }
    return 0;
}
