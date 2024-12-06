#include <cstdint>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <ws2tcpip.h>

struct in_addr addr;
// �� IP ��ַ�ַ���ת��Ϊ 32 λ����
uint32_t ip2Int(const std::string ip) {
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        std::cerr << "Invalid IP address: " << ip << std::endl;
        return 0;
    }
    // ת��Ϊ�����ֽ���
    return ntohl(addr.s_addr);
}

// ��� IP �Ƿ����� CIDR ��ַ��
bool ip_in_cidr(const std::string ip, const std::string cidr) {
    size_t pos = cidr.find('/');
    std::string cidr_ip_str = cidr.substr(0, pos);
    int netmask_len = std::stoi(cidr.substr(pos + 1));

    // ��IP��ַת��Ϊ32λ����
    uint32_t ip_value = ip2Int(ip);
    // ��CIDR�����ַת��Ϊ32λ����
    uint32_t cidr_ip_value = ip2Int(cidr_ip_str);

    // �����������루CIDR�������ȣ�
    uint32_t ip_mask = (0xFFFFFFFF << (32 - netmask_len)) & 0xFFFFFFFF;

    // ���IP�Ƿ���CIDR��ַ����
    return (ip_value & ip_mask) == (cidr_ip_value & ip_mask);
}

std::string GetIPv4(std::string cidr) {
    //PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //�õ��ṹ���С,����GetAdaptersInfo����
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        //����������ص���ERROR_BUFFER_OVERFLOW
        //��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
        //��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
        //�ͷ�ԭ�����ڴ�ռ�
        delete pIpAdapterInfo;
        //���������ڴ�ռ������洢����������Ϣ
        pIpAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[stSize];
        //�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }
    if (ERROR_SUCCESS == nRel) {
        //���������Ϣ
        //�����ж�����,���ͨ��ѭ��ȥ�ж�
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
    //�ͷ��ڴ�ռ�
    if (pIpAdapterInfo) {
        delete pIpAdapterInfo;
    }
    return "";
}

int main() {
    //ץȡ��������IP��ɸѡcidr��Χ�ڵ�Ŀ��
    std::string ip= GetIPv4("192.168.1.43/24");
    if(ip!="") {
        std::cout<<ip<<std::endl;
    }
    else {
        std::cout<<"error: can not get ip."<<std::endl;
    }
    return 0;
}
