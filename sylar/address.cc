#include "address.h"
#include "log.h"
#include <sstream>
#include <netdb.h>
#include <ifaddrs.h>
#include <stddef.h>

#include "endian.h"

namespace sylar {

static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");
//这段代码是一个通用的模板函数，用于创建掩码（mask）
//根据子网掩码位数，计算子网掩码对应的十进制数
template<class T>
static T CreateMask(uint32_t bits) {
    return (1 << (sizeof(T) * 8 - bits)) - 1;
}
//这段代码实现了一个通用的函数 CountBytes，用于计算给定整数 value 的二进制表示中包含的 1 的个数。
//根据子网掩码对应的十进制数，计算子网掩码的位数
template<class T>
static uint32_t CountBytes(T value) {
    uint32_t result = 0;
    //使用了 Brian Kernighan 算法来计算给定整数 value 的二进制表示中包含的 1 的个数
    for(; value; ++result) {
        //按位与赋值运算符,它将右侧表达式的结果与左侧的变量进行按位与操作，并将结果赋值给左侧的变量。
        value &= value - 1;
    }
    return result;
}

Address::ptr Address::LookupAny(const std::string& host,
                                int family, int type, int protocol) {
    std::vector<Address::ptr> result;
    if(Lookup(result, host, family, type, protocol)) {
        return result[0];
    }
    return nullptr;
}

IPAddress::ptr Address::LookupAnyIPAddress(const std::string& host,  //返回的是IPAddress类型而Lookup返回的是Address类型
                                int family, int type, int protocol) {
    std::vector<Address::ptr> result;
    if(Lookup(result, host, family, type, protocol)) {
        //for(auto& i : result) {
        //    std::cout << i->toString() << std::endl;
        //}
        //根据强制转换是否成功来筛选IP地址信息
        for(auto& i : result) {
            IPAddress::ptr v = std::dynamic_pointer_cast<IPAddress>(i);//将i转换成IPAddress类型的智能指针，只有派生类才能转换，否则为空
            if(v) {
                return v;
            }
        }
    }
    return nullptr;
}

// 首先这里的host参数有以下几种情况：
// 1.【IPv6有端口】，如：[FC00:0000:130F:0000:0000:09C0:876A:130B]:8080
// 2.【IPv6无端口】，如：FC00:0000:130F:0000:0000:09C0:876A:130B
// 3.【IPv4有端口】，如：192.168.0.1:8080
// 4.【IPv4无端口】，如：192.168.0.1
bool Address::Lookup(std::vector<Address::ptr>& result, const std::string& host,
                     int family, int type, int protocol) {
    addrinfo hints, *results, *next;//通过调用getaddrinfo()函数可以填充并返回一个或多个addrinfo结构，其中包含了特定主机名和服务名对应的可用地址信息。
    hints.ai_flags = 0;// 地址信息标志
    hints.ai_family = family;// 地址族(AF_INET, AF_INET6, AF_UNSPEC)
    hints.ai_socktype = type;// 套接字类型(SOCK_STREAM, SOCK_DGRAM)
    hints.ai_protocol = protocol;// 协议号(IPPROTO_TCP, IPPROTO_UDP)，或0表示任意协议
    hints.ai_addrlen = 0;// 地址长度
    hints.ai_canonname = NULL;// 网络地址结构指针
    hints.ai_addr = NULL;// 规范名字(主机名或服务名)
    hints.ai_next = NULL;// 指向下一个addrinfo结构的指针
    // IP地址
    std::string node;
    // 对应端口
    const char* service = NULL;
    // 检查是否是指定端口的IPv6协议 
    // 如：[FC00:0000:130F:0000:0000:09C0:876A:130B]:8080
    // 如果host非空且第一个是符号 '[',证明有可能是带端口的IPv6
    //检查 ipv6address serivce
    if(!host.empty() && host[0] == '[') {//“memchr”通常是指 C 或 C++ 标准库中的一个函数，用于在指定的内存区域中查找特定的字符。它会返回指向首次出现指定字符的指针，如果未找到则返回空指针。
        const char* endipv6 = (const char*)memchr(host.c_str() + 1, ']', host.size() - 1);//str -- 指向要执行搜索的内存块。
// c -- 以 int 形式传递的值，但是函数在每次字节搜索时是使用该值的无符号字符形式。
// n -- 要被分析的字节数。
        if(endipv6) {
            //TODO check out of range
            // 判断字符 ']' 的下一位是否是字符 ':'
            if(*(endipv6 + 1) == ':') {
                // 如果是字符 ':' 那么端口号的起始地址就是 endipv6 + 2 也就是字符 ']' 后的第二个开始到最后
                service = endipv6 + 2;
            }
            // 将IP地址部分截取，此时node就是 FC00:0000:130F:0000:0000:09C0:876A:130B
            node = host.substr(1, endipv6 - host.c_str() - 1);
        }
    }

    //检查 node serivce
    // 检查IP地址是否为空，为空证明当前host并不是【IPv6有端口】的模式,纳闷就是IPV4地址
    if(node.empty()) {
        // 查找第一个字符 ':' 因为IPv4有端口模式是根据 ':' 来分隔 IP:端口 的
        service = (const char*)memchr(host.c_str(), ':', host.size());
        // 判断是否存在字符 ':'
        if(service) {
            // 判断是否只有一个字符 ':',如果只有一个，则证明是【IPv4有端口】模式，否则是【IPv6无端口】模式
            if(!memchr(service + 1, ':', host.c_str() + host.size() - service - 1)) {
                // 确定是 【IPv4有端口】模式 如：192.168.0.1:8080
            	// 提取node 192.168.0.1
                node = host.substr(0, service - host.c_str());
                // 提取端口起始地址是 ':'的后一位开始到最后 即 8080
                ++service;
            }
        }
    }
    // 如果到此 node 还未提取出来，那么证明host只有以下两种模式的可能：
	// 1.host是 【IPv6无端口】 如：FC00:0000:130F:0000:0000:09C0:876A:130B
	// 2.host是 【IPv4无端口】 如：192.168.0.1
    if(node.empty()) {
        node = host;
    }
    // getaddrinfo函数根据给定的主机名和服务名，返回一个struct addrinfo结构链表
    // 每个struct addrinfo结构都包含一个互联网地址。  
    """
        int  getaddrinfo(
        const char* nodename,
        const char* servname,
        const struct addrinfo* hints,
        struct addrinfo** res
        );
        *  nodename:节点名可以是主机名，也可以是数字地址。（IPV4的10进点分，或是IPV6的16进制）
        *  servname:包含十进制数的端口号或服务名如（ftp,http）
        *  hints:是一个空指针或指向一个addrinfo结构的指针，由调用者填写关于它所想返回的信息类型的线索。
        *  res:存放返回addrinfo结构链表的指针,指向由一个或多个addrinfo结构体组成的链表，包含了主机的响应信息
        * 返回值：成功返回0，失败返回非零的 sockets error code
    """
    int error = getaddrinfo(node.c_str(), service, &hints, &results);//调用getaddrinfo()函数可以填充并返回一个或多个addrinfo结构
    if(error) {
        SYLAR_LOG_DEBUG(g_logger) << "Address::Lookup getaddress(" << host << ", "
            << family << ", " << type << ") err=" << error << " errstr="
            << gai_strerror(error);
        return false;
    }
    // 遍历互联网地址链表
    next = results;
    while(next) {
        // 将互联网地址链表拆平结构，存储到vector中便于后续操作
        result.push_back(Create(next->ai_addr, (socklen_t)next->ai_addrlen));
        //一个ip/端口可以对应多种接字类型，比如SOCK_STREAM, SOCK_DGRAM, SOCK_RAW，所以这里会返回重复的结果
        //SYLAR_LOG_INFO(g_logger) << ((sockaddr_in*)next->ai_addr)->sin_addr.s_addr;
        next = next->ai_next;
    }
    // 释放链表的内存空间
    freeaddrinfo(results);
    return !result.empty();
}
// 获取本机互联网地址信息
bool Address::GetInterfaceAddresses(std::multimap<std::string
                    ,std::pair<Address::ptr, uint32_t> >& result,
                    int family) {
    struct ifaddrs *next, *results;  //接口相关的结构体
    if(getifaddrs(&results) != 0) {//返回失败，报错
        SYLAR_LOG_DEBUG(g_logger) << "Address::GetInterfaceAddresses getifaddrs "
            " err=" << errno << " errstr=" << strerror(errno);
        return false;
    }

    try {
        for(next = results; next; next = next->ifa_next) {
            Address::ptr addr;
            uint32_t prefix_len = ~0u; //~0u 表示对无符号 32 位整数 0 进行按位取反操作，其结果是所有位都为 1
            if(family != AF_UNSPEC && family != next->ifa_addr->sa_family) {
                continue;
            }
            switch(next->ifa_addr->sa_family) {
                case AF_INET:
                    {
                        addr = Create(next->ifa_addr, sizeof(sockaddr_in));
                        uint32_t netmask = ((sockaddr_in*)next->ifa_netmask)->sin_addr.s_addr;
                        prefix_len = CountBytes(netmask);
                    }
                    break;
                case AF_INET6:
                    {
                        addr = Create(next->ifa_addr, sizeof(sockaddr_in6));
                        in6_addr& netmask = ((sockaddr_in6*)next->ifa_netmask)->sin6_addr;
                        prefix_len = 0;
                        for(int i = 0; i < 16; ++i) {
                            prefix_len += CountBytes(netmask.s6_addr[i]);
                        }
                    }
                    break;
                default:
                    break;
            }

            if(addr) {
                result.insert(std::make_pair(next->ifa_name,
                            std::make_pair(addr, prefix_len)));
            }
        }
    } catch (...) {
        SYLAR_LOG_ERROR(g_logger) << "Address::GetInterfaceAddresses exception";
        freeifaddrs(results);
        return false;
    }
    freeifaddrs(results);
    return !result.empty();
}
//函数重载
bool Address::GetInterfaceAddresses(std::vector<std::pair<Address::ptr, uint32_t> >&result
                    ,const std::string& iface, int family) {
    if(iface.empty() || iface == "*") {
        if(family == AF_INET || family == AF_UNSPEC) {
            result.push_back(std::make_pair(Address::ptr(new IPv4Address()), 0u));
        }
        if(family == AF_INET6 || family == AF_UNSPEC) {
            result.push_back(std::make_pair(Address::ptr(new IPv6Address()), 0u));
        }
        return true;
    }

    std::multimap<std::string
          ,std::pair<Address::ptr, uint32_t> > results;

    if(!GetInterfaceAddresses(results, family)) {
        return false;
    }

    auto its = results.equal_range(iface);
    for(; its.first != its.second; ++its.first) {
        result.push_back(its.first->second);
    }
    return !result.empty();
}

int Address::getFamily() const {
    return getAddr()->sa_family;
}

std::string Address::toString() const {
    std::stringstream ss;
    insert(ss);
    return ss.str();
}
//创建地址
Address::ptr Address::Create(const sockaddr* addr, socklen_t addrlen) {
    if(addr == nullptr) {
        return nullptr;
    }

    Address::ptr result;
    switch(addr->sa_family) { //协议族
        case AF_INET:
            result.reset(new IPv4Address(*(const sockaddr_in*)addr)); //将 result 重新设置为一个新创建的 IPv4Address 对象，该对象通过对给定的 addr 指针进行类型转换为 const sockaddr_in * 后进行初始化。
            break;
        case AF_INET6:
            result.reset(new IPv6Address(*(const sockaddr_in6*)addr));
            break;
        default:
            result.reset(new UnknownAddress(*addr));
            break;
    }
    return result;
}
//重载<运算符
bool Address::operator<(const Address& rhs) const {
    socklen_t minlen = std::min(getAddrLen(), rhs.getAddrLen()); //计算了两个地址的最小长度（minlen），以便在比较时不越界。
    int result = memcmp(getAddr(), rhs.getAddr(), minlen);//返回值得大小表示了字符串的长度大小
    if(result < 0) {
        return true;
    } else if(result > 0) {
        return false;
    } else if(getAddrLen() < rhs.getAddrLen()) {
        return true;
    }
    return false;
}
//运算符重载，作为自建类型的成员函数, 定义在类的内部
//此时operator的参数数目比具体重载的运算符操作数数目少一, 因为此时使用的一个隐含参数为* this, 并将其作为左操作数(第一个操作数)
bool Address::operator==(const Address& rhs) const {
    return getAddrLen() == rhs.getAddrLen()
        && memcmp(getAddr(), rhs.getAddr(), getAddrLen()) == 0;  //比较两个内存块的内容是否相等,getAddrLen()为两块内存的长度
}

bool Address::operator!=(const Address& rhs) const {
    return !(*this == rhs);
}

IPAddress::ptr IPAddress::Create(const char* address, uint16_t port) {
    //“addrinfo”是一个结构体的名称。该结构体包含了一系列与地址信息相关的成员变量，如地址信息标志、地址族、套接字类型、协议号、地址长度、网络地址结构指针、规范名字以及指向下一个“addrinfo”结构体的指针等。这些成员变量共同描述了与网络地址相关的各种属性和信息。
    addrinfo hints, *results;
    memset(&hints, 0, sizeof(addrinfo));//memset 是 C 和 C++ 中的一个库函数，用于初始化内存

    hints.ai_flags = AI_NUMERICHOST;// 地址信息标志
    hints.ai_family = AF_UNSPEC; // 地址族(AF_INET, AF_INET6, AF_UNSPEC)

    int error = getaddrinfo(address, NULL, &hints, &results);
    if(error) {
        SYLAR_LOG_DEBUG(g_logger) << "IPAddress::Create(" << address
            << ", " << port << ") error=" << error
            << " errno=" << errno << " errstr=" << strerror(errno);
        return nullptr;
    }

    try {
//“dynamic_pointer_cast”通常是 C++ 中的一个操作，用于在智能指针类型之间进行动态类型转换。它用于检查一个智能指针所指向的对象是否可以安全地转换为目标类型，如果可以，则返回一个指向目标类型的智能指针；否则返回空指针。这种转换是在运行时进行类型检查的。
        IPAddress::ptr result = std::dynamic_pointer_cast<IPAddress>(
                Address::Create(results->ai_addr, (socklen_t)results->ai_addrlen)); //Address类型转为IPAddress类型，及父类转子类
        if(result) {
            result->setPort(port);
        }
        freeaddrinfo(results);
        return result;
    } catch (...) {
        freeaddrinfo(results);
        return nullptr;
    }
}

IPv4Address::ptr IPv4Address::Create(const char* address, uint16_t port) {
    IPv4Address::ptr rt(new IPv4Address); //这段代码创建了一个指向 IPv4Address 类型的智能指针 rt，并通过 new 操作符初始化了一个新的 IPv4Address 对象。
    rt->m_addr.sin_port = byteswapOnLittleEndian(port); //大小端转换
    int result = inet_pton(AF_INET, address, &rt->m_addr.sin_addr); //“inet_pton”是一个函数，用于将点分十进制的 IPv4 地址字符串或 IPv6 地址字符串转换为网络字节序的二进制地址格式。
    if(result <= 0) {
        SYLAR_LOG_DEBUG(g_logger) << "IPv4Address::Create(" << address << ", "
                << port << ") rt=" << result << " errno=" << errno
                << " errstr=" << strerror(errno);
        return nullptr;
    }
    return rt;
}

IPv4Address::IPv4Address(const sockaddr_in& address) {
    m_addr = address;
}

IPv4Address::IPv4Address(uint32_t address, uint16_t port) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin_family = AF_INET;
    m_addr.sin_port = byteswapOnLittleEndian(port);
    m_addr.sin_addr.s_addr = byteswapOnLittleEndian(address);
}
//m_addr 是 IPv4Address 类的一个成员变量，存储了 IPv4 地址信息。通过类型转换 (sockaddr*)&m_addr，将 m_addr 转换为 sockaddr 类型的指针。
sockaddr* IPv4Address::getAddr() {
    return (sockaddr*)&m_addr;
}
//但它是一个常量成员函数，意味着它不会修改类的成员变量。返回值类型是 const sockaddr*，表示返回的指针指向的内容是不可修改的。
const sockaddr* IPv4Address::getAddr() const {
    return (sockaddr*)&m_addr;
}
//const 关键字的作用是表明 getAddrLen 函数是一个常量成员函数
socklen_t IPv4Address::getAddrLen() const {
    return sizeof(m_addr);
}

//将 IPv4 地址和端口号格式化输出到 std::ostream 流中
std::ostream& IPv4Address::insert(std::ostream& os) const {
    uint32_t addr = byteswapOnLittleEndian(m_addr.sin_addr.s_addr);//这行代码将 m_addr.sin_addr.s_addr（存储 IPv4 地址的成员变量）进行字节序转换，以确保在小端系统上正确显示地址。
    os << ((addr >> 24) & 0xff) << "."
       << ((addr >> 16) & 0xff) << "."
       << ((addr >> 8) & 0xff) << "."
       << (addr & 0xff);
    os << ":" << byteswapOnLittleEndian(m_addr.sin_port);
    return os;//函数返回修改后的输出流 os
}
//获取该地址的广播地址
IPAddress::ptr IPv4Address::broadcastAddress(uint32_t prefix_len) {
    if(prefix_len > 32) {
        return nullptr;
    }

    sockaddr_in baddr(m_addr);
    baddr.sin_addr.s_addr |= byteswapOnLittleEndian(
            CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(baddr));
}
//获取该地址的网段
IPAddress::ptr IPv4Address::networdAddress(uint32_t prefix_len) {
    if(prefix_len > 32) {
        return nullptr;
    }

    sockaddr_in baddr(m_addr);
    baddr.sin_addr.s_addr &= byteswapOnLittleEndian(
            CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(baddr));
}
//获取子网掩码地址
IPAddress::ptr IPv4Address::subnetMask(uint32_t prefix_len) {
    sockaddr_in subnet;
    memset(&subnet, 0, sizeof(subnet));
    subnet.sin_family = AF_INET;
    subnet.sin_addr.s_addr = ~byteswapOnLittleEndian(CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(subnet));
}

uint32_t IPv4Address::getPort() const {
    return byteswapOnLittleEndian(m_addr.sin_port);
}

void IPv4Address::setPort(uint16_t v) {
    m_addr.sin_port = byteswapOnLittleEndian(v);
}

IPv6Address::ptr IPv6Address::Create(const char* address, uint16_t port) {
    IPv6Address::ptr rt(new IPv6Address);
    rt->m_addr.sin6_port = byteswapOnLittleEndian(port);
    int result = inet_pton(AF_INET6, address, &rt->m_addr.sin6_addr);
    if(result <= 0) {
        SYLAR_LOG_DEBUG(g_logger) << "IPv6Address::Create(" << address << ", "
                << port << ") rt=" << result << " errno=" << errno
                << " errstr=" << strerror(errno);
        return nullptr;
    }
    return rt;
}

IPv6Address::IPv6Address() {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin6_family = AF_INET6;
}

IPv6Address::IPv6Address(const sockaddr_in6& address) {
    m_addr = address;
}

IPv6Address::IPv6Address(const uint8_t address[16], uint16_t port) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin6_family = AF_INET6;
    m_addr.sin6_port = byteswapOnLittleEndian(port);
    memcpy(&m_addr.sin6_addr.s6_addr, address, 16);
}

sockaddr* IPv6Address::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* IPv6Address::getAddr() const {
    return (sockaddr*)&m_addr;
}

socklen_t IPv6Address::getAddrLen() const {
    return sizeof(m_addr);
}

std::ostream& IPv6Address::insert(std::ostream& os) const {
    os << "[";
    uint16_t* addr = (uint16_t*)m_addr.sin6_addr.s6_addr;
    bool used_zeros = false;
    for(size_t i = 0; i < 8; ++i) {
        if(addr[i] == 0 && !used_zeros) {
            continue;
        }
        if(i && addr[i - 1] == 0 && !used_zeros) {
            os << ":";
            used_zeros = true;
        }
        if(i) {
            os << ":";
        }
        os << std::hex << (int)byteswapOnLittleEndian(addr[i]) << std::dec;
    }

    if(!used_zeros && addr[7] == 0) {
        os << "::";
    }

    os << "]:" << byteswapOnLittleEndian(m_addr.sin6_port);
    return os;
}

IPAddress::ptr IPv6Address::broadcastAddress(uint32_t prefix_len) {
    sockaddr_in6 baddr(m_addr);
    baddr.sin6_addr.s6_addr[prefix_len / 8] |=
        CreateMask<uint8_t>(prefix_len % 8);
    for(int i = prefix_len / 8 + 1; i < 16; ++i) {
        baddr.sin6_addr.s6_addr[i] = 0xff;
    }
    return IPv6Address::ptr(new IPv6Address(baddr));
}

IPAddress::ptr IPv6Address::networdAddress(uint32_t prefix_len) {
    sockaddr_in6 baddr(m_addr);
    baddr.sin6_addr.s6_addr[prefix_len / 8] &=
        CreateMask<uint8_t>(prefix_len % 8);
    for(int i = prefix_len / 8 + 1; i < 16; ++i) {
        baddr.sin6_addr.s6_addr[i] = 0x00;
    }
    return IPv6Address::ptr(new IPv6Address(baddr));
}

IPAddress::ptr IPv6Address::subnetMask(uint32_t prefix_len) {
    sockaddr_in6 subnet;
    memset(&subnet, 0, sizeof(subnet));
    subnet.sin6_family = AF_INET6;
    subnet.sin6_addr.s6_addr[prefix_len /8] =
        ~CreateMask<uint8_t>(prefix_len % 8);

    for(uint32_t i = 0; i < prefix_len / 8; ++i) {
        subnet.sin6_addr.s6_addr[i] = 0xff;
    }
    return IPv6Address::ptr(new IPv6Address(subnet));
}

uint32_t IPv6Address::getPort() const {
    return byteswapOnLittleEndian(m_addr.sin6_port);
}

void IPv6Address::setPort(uint16_t v) {
    m_addr.sin6_port = byteswapOnLittleEndian(v);
}

static const size_t MAX_PATH_LEN = sizeof(((sockaddr_un*)0)->sun_path) - 1;

UnixAddress::UnixAddress() {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sun_family = AF_UNIX;
    m_length = offsetof(sockaddr_un, sun_path) + MAX_PATH_LEN;
}

UnixAddress::UnixAddress(const std::string& path) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sun_family = AF_UNIX;
    m_length = path.size() + 1;

    if(!path.empty() && path[0] == '\0') {
        --m_length;
    }

    if(m_length > sizeof(m_addr.sun_path)) {
        throw std::logic_error("path too long");
    }
    memcpy(m_addr.sun_path, path.c_str(), m_length);
    m_length += offsetof(sockaddr_un, sun_path);
}

void UnixAddress::setAddrLen(uint32_t v) {
    m_length = v;
}

sockaddr* UnixAddress::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* UnixAddress::getAddr() const {
    return (sockaddr*)&m_addr;
}

socklen_t UnixAddress::getAddrLen() const {
    return m_length;
}

std::string UnixAddress::getPath() const {
    std::stringstream ss;
    if(m_length > offsetof(sockaddr_un, sun_path)
            && m_addr.sun_path[0] == '\0') {
        ss << "\\0" << std::string(m_addr.sun_path + 1,
                m_length - offsetof(sockaddr_un, sun_path) - 1);
    } else {
        ss << m_addr.sun_path;
    }
    return ss.str();
}

std::ostream& UnixAddress::insert(std::ostream& os) const {
    if(m_length > offsetof(sockaddr_un, sun_path)
            && m_addr.sun_path[0] == '\0') {
        return os << "\\0" << std::string(m_addr.sun_path + 1,
                m_length - offsetof(sockaddr_un, sun_path) - 1);
    }
    return os << m_addr.sun_path;
}

UnknownAddress::UnknownAddress(int family) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sa_family = family;
}

UnknownAddress::UnknownAddress(const sockaddr& addr) {
    m_addr = addr;
}

sockaddr* UnknownAddress::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* UnknownAddress::getAddr() const {
    return &m_addr;
}

socklen_t UnknownAddress::getAddrLen() const {
    return sizeof(m_addr);
}

std::ostream& UnknownAddress::insert(std::ostream& os) const {
    os << "[UnknownAddress family=" << m_addr.sa_family << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, const Address& addr) {
    return addr.insert(os);
}

}
