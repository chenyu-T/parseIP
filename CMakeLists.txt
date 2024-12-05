cmake_minimum_required(VERSION 3.28)
project(parseIP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#头文件路径
include_directories(E:/CAE/parseIP/include)
#链接库路径
link_directories(E:/CAE/parseIP/lib)
#添加可执行文件
add_executable(parseIP src/Test.cpp
)

# 配置头文件路径（针对 parseIP 目标）
target_include_directories(parseIP PRIVATE E:/CAE/parseIP/include)
# 配置链接库路径（针对 parseIP 目标）
target_link_directories(parseIP PRIVATE E:/CAE/parseIP/lib)
# 链接库（注意顺序：wpcap 在前，Packet 在后）
target_link_libraries(parseIP PRIVATE wpcap.lib Packet.lib Ws2_32.lib)

