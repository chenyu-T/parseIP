#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <string>
#include <pcap.h>

using namespace std;

// 输出线条
void PrintLine(int x)
{
    for (size_t i = 0; i < x; i++)
    {
        printf("-");
    }
    printf("\n");
}

// 枚举当前网卡
int enumAdapters()
{
    pcap_if_t *allAdapters;    // 所有网卡设备保存
    pcap_if_t *ptr;            // 用于遍历的指针
    int index = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
    {
        PrintLine(100);
        printf("索引 \t 网卡名 \n");
        PrintLine(100);

        /* 打印网卡信息列表 */
        for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
        {
            ++index;
            if (ptr->description)
            {
                printf("[ %d ] \t [ %s ] \n", index - 1, ptr->description);
            }
        }
    }

    /* 不再需要设备列表了，释放它 */
    pcap_freealldevs(allAdapters);
    return index;
}
int main(int argc, char* argv[])
{
    enumAdapters();
    system("pause");
    return 0;
}