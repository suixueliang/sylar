#include "socket.h"
#include "iomanager.h"
#include "fd_manager.h"
#include "log.h"
#include "macro.h"
#include "hook.h"
#include <limits.h>

namespace sylar {

static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

Socket::ptr Socket::CreateTCP(sylar::Address::ptr address) {
    Socket::ptr sock(new Socket(address->getFamily(), TCP, 0));
    return sock;
}

Socket::ptr Socket::CreateUDP(sylar::Address::ptr address) {
    Socket::ptr sock(new Socket(address->getFamily(), UDP, 0));
    sock->newSock();
    sock->m_isConnected = true;
    return sock;
}

Socket::ptr Socket::CreateTCPSocket() {
    Socket::ptr sock(new Socket(IPv4, TCP, 0));
    return sock;
}

Socket::ptr Socket::CreateUDPSocket() {
    Socket::ptr sock(new Socket(IPv4, UDP, 0));
    sock->newSock();
    sock->m_isConnected = true;
    return sock;
}

Socket::ptr Socket::CreateTCPSocket6() {
    Socket::ptr sock(new Socket(IPv6, TCP, 0));
    return sock;
}

Socket::ptr Socket::CreateUDPSocket6() {
    Socket::ptr sock(new Socket(IPv6, UDP, 0));
    sock->newSock();
    sock->m_isConnected = true;
    return sock;
}

Socket::ptr Socket::CreateUnixTCPSocket() {
    Socket::ptr sock(new Socket(UNIX, TCP, 0));
    return sock;
}

Socket::ptr Socket::CreateUnixUDPSocket() {
    Socket::ptr sock(new Socket(UNIX, UDP, 0));
    return sock;
}

Socket::Socket(int family, int type, int protocol)
    :m_sock(-1)
    ,m_family(family)
    ,m_type(type)
    ,m_protocol(protocol)
    ,m_isConnected(false) {
}

Socket::~Socket() {
    close();
}

int64_t Socket::getSendTimeout() {
    FdCtx::ptr ctx = FdMgr::GetInstance()->get(m_sock);
    if(ctx) {
        return ctx->getTimeout(SO_SNDTIMEO);
    }
    return -1;
}

void Socket::setSendTimeout(int64_t v) {
    struct timeval tv{int(v / 1000), int(v % 1000 * 1000)};
    setOption(SOL_SOCKET, SO_SNDTIMEO, tv);
}

int64_t Socket::getRecvTimeout() {
    FdCtx::ptr ctx = FdMgr::GetInstance()->get(m_sock);
    if(ctx) {
        return ctx->getTimeout(SO_RCVTIMEO);
    }
    return -1;
}

void Socket::setRecvTimeout(int64_t v) {
    struct timeval tv{int(v / 1000), int(v % 1000 * 1000)};
    setOption(SOL_SOCKET, SO_RCVTIMEO, tv);
}

bool Socket::getOption(int level, int option, void* result, socklen_t* len) {
    int rt = getsockopt(m_sock, level, option, result, (socklen_t*)len);
    if(rt) {
        SYLAR_LOG_DEBUG(g_logger) << "getOption sock=" << m_sock
            << " level=" << level << " option=" << option
            << " errno=" << errno << " errstr=" << strerror(errno);
        return false;
    }
    return true;
}

bool Socket::setOption(int level, int option, const void* result, socklen_t len) {
    if(setsockopt(m_sock, level, option, result, (socklen_t)len)) {
        SYLAR_LOG_DEBUG(g_logger) << "setOption sock=" << m_sock
            << " level=" << level << " option=" << option
            << " errno=" << errno << " errstr=" << strerror(errno);
        return false;
    }
    return true;
}

Socket::ptr Socket::accept() {
    Socket::ptr sock(new Socket(m_family, m_type, m_protocol));//这段代码创建了一个名为 sock 的 Socket::ptr 类型的对象，并通过 new 操作符调用 Socket 类的构造函数进行初始化，传递了 m_family、m_type 和 m_protocol 这几个参数。
    int newsock = ::accept(m_sock, nullptr, nullptr);//这段代码定义了一个整型变量 newsock ，并通过调用 ::accept 函数来获取新的套接字描述符。其中 m_sock 是已有的套接字，后面的两个 nullptr 分别用于指定客户端地址和地址长度，在当前场景中未被使用。
    if(newsock == -1) {
        SYLAR_LOG_ERROR(g_logger) << "accept(" << m_sock << ") errno="
            << errno << " errstr=" << strerror(errno);
        return nullptr;
    }
    if(sock->init(newsock)) {
        return sock;
    }
    return nullptr;
}

bool Socket::init(int sock) {
    FdCtx::ptr ctx = FdMgr::GetInstance()->get(sock);
    if(ctx && ctx->isSocket() && !ctx->isClose()) {
        m_sock = sock;
        m_isConnected = true;
        initSock();
        getLocalAddress();
        getRemoteAddress();
        return true;
    }
    return false;
}

bool Socket::bind(const Address::ptr addr) {
    //m_localAddress = addr;
    if(!isValid()) {
        newSock();
        if(SYLAR_UNLIKELY(!isValid())) {
            return false;
        }
    }

    if(SYLAR_UNLIKELY(addr->getFamily() != m_family)) {
        SYLAR_LOG_ERROR(g_logger) << "bind sock.family("
            << m_family << ") addr.family(" << addr->getFamily()
            << ") not equal, addr=" << addr->toString();
        return false;
    }

    UnixAddress::ptr uaddr = std::dynamic_pointer_cast<UnixAddress>(addr);//通过 std::dynamic_pointer_cast 函数将输入的 addr 指针转换为 UnixAddress 类型的智能指针。
    if(uaddr) {//这段代码的意思是：如果 uaddr 不为空，创建一个 Unix TCP 套接字 sock 。如果 sock 成功连接到 uaddr ，则返回 false 。否则，使用 sylar::FSUtil::Unlink 函数删除 uaddr 的路径。
        Socket::ptr sock = Socket::CreateUnixTCPSocket();
        if(sock->connect(uaddr)) {
            return false;
        } else {
            sylar::FSUtil::Unlink(uaddr->getPath(), true);
        }
    }

    if(::bind(m_sock, addr->getAddr(), addr->getAddrLen())) {//如果调用 ::bind 函数将 m_sock 与指定的地址和地址长度进行绑定操作失败，就会记录一条错误日志，其中包含错误码 errno 和对应的错误描述字符串 strerror(errno) ，然后返回 false ，表示操作不成功。
        SYLAR_LOG_ERROR(g_logger) << "bind error errrno=" << errno
            << " errstr=" << strerror(errno);
        return false;
    }
    getLocalAddress();
    return true;
}

bool Socket::reconnect(uint64_t timeout_ms) {
    if(!m_remoteAddress) {
        SYLAR_LOG_ERROR(g_logger) << "reconnect m_remoteAddress is null";
        return false;
    }
    m_localAddress.reset();
    return connect(m_remoteAddress, timeout_ms);
}
//这段代码主要处理了根据超时时间（timeout_ms）的不同情况来进行连接操作。如果超时时间为特定值（uint64_t）-1 ，则使用常规的连接函数（::connect）进行连接。若连接失败，会记录错误日志（SYLAR_LOG_ERROR），关闭连接并返回 false 。否则，如果有指定的超时时间，就使用带超时的连接函数（::connect_with_timeout）进行连接。若在超时时间内连接失败，同样会记录错误日志、关闭连接并返回 false 。
bool Socket::connect(const Address::ptr addr, uint64_t timeout_ms) {
    m_remoteAddress = addr;
    if(!isValid()) {//通过调用isValid()方法检查当前Socket是否有效
        newSock();//如果无效，则调用newSock()方法来创建新的Socket，并再次检查其有效性。如果Socket仍然无效，函数返回false。
        if(SYLAR_UNLIKELY(!isValid())) {
            return false;
        }
    }

    if(SYLAR_UNLIKELY(addr->getFamily() != m_family)) {//通过比较远程地址的地址族（addr->getFamily()）和Socket的地址族（m_family）来确保它们匹配。如果不匹配，则记录错误日志并返回false。
        SYLAR_LOG_ERROR(g_logger) << "connect sock.family("
            << m_family << ") addr.family(" << addr->getFamily()
            << ") not equal, addr=" << addr->toString();
        return false;
    }

    if(timeout_ms == (uint64_t)-1) {//如果timeout_ms被设置为(uint64_t)-1，表示不使用超时机制，直接调用::connect()函数尝试连接。如果连接失败（::connect()返回非零值），则记录错误日志，关闭Socket，并返回false。
        if(::connect(m_sock, addr->getAddr(), addr->getAddrLen())) {
            SYLAR_LOG_ERROR(g_logger) << "sock=" << m_sock << " connect(" << addr->toString()
                << ") error errno=" << errno << " errstr=" << strerror(errno);
            close();
            return false;
        }
    } else {//如果指定了超时时间（timeout_ms非(uint64_t)-1），则调用::connect_with_timeout()函数尝试在指定时间内建立连接。
        if(::connect_with_timeout(m_sock, addr->getAddr(), addr->getAddrLen(), timeout_ms)) {
            SYLAR_LOG_ERROR(g_logger) << "sock=" << m_sock << " connect(" << addr->toString()
                << ") timeout=" << timeout_ms << " error errno="
                << errno << " errstr=" << strerror(errno);
            close();
            return false;
        }
    }
    m_isConnected = true;
    getRemoteAddress();
    getLocalAddress();
    return true;
}

bool Socket::listen(int backlog) {
    if(!isValid()) {
        SYLAR_LOG_ERROR(g_logger) << "listen error sock=-1";
        return false;
    }
    if(::listen(m_sock, backlog)) {//::listen 是对系统调用 listen 的引用，前面的 :: 表示这是一个全局作用域中的 listen，而不是当前类或命名空间中定义的同名函数（尽管在这个上下文中，它实际上可能是多余的，因为 listen 很可能是一个全局可见的系统调用）。
        SYLAR_LOG_ERROR(g_logger) << "listen error errno=" << errno
            << " errstr=" << strerror(errno);
        return false;
    }
    return true;
}

bool Socket::close() {
    if(!m_isConnected && m_sock == -1) {
        return true;
    }
    m_isConnected = false;
    if(m_sock != -1) {
        ::close(m_sock);
        m_sock = -1;
    }
    return false;
}

int Socket::send(const void* buffer, size_t length, int flags) {//定义了一个名为 Socket 的类中的 send 方法。该方法接收三个参数：一个指向 void 类型数据的指针 buffer 、一个表示数据长度的 size_t 类型变量 length 以及一个整型的标志 flags 。方法内部首先判断当前连接状态，如果已连接（isConnected() 为真），则调用系统函数 ::send 发送数据，并返回发送的结果；如果未连接，则返回 -1 。
    if(isConnected()) {
        return ::send(m_sock, buffer, length, flags);
    }
    return -1;
}

int Socket::send(const iovec* buffers, size_t length, int flags) {//函数首先检查是否处于连接状态，如果是，则创建一个 msghdr 结构体 msg 并进行初始化。然后，将传入的 buffers 赋值给 msg.msg_iov，将 length 赋值给 msg.msg_iovlen，最后通过 ::sendmsg(m_sock, &msg, flags) 进行发送操作并返回结果。如果未处于连接状态，则返回 -1 。
    if(isConnected()) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));//使用了 memset 函数将 msg 所指向的内存区域初始化为 0 。
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        return ::sendmsg(m_sock, &msg, flags);
    }
    return -1;
}

int Socket::sendTo(const void* buffer, size_t length, const Address::ptr to, int flags) {//该函数接收一些参数，包括一个指向 void 类型的缓冲区指针 buffer 、缓冲区长度 length 、一个 Address::ptr 类型的对象 to 以及一个整数类型的标志 flags 。函数内部首先检查是否处于连接状态，如果是，则使用 ::sendto 函数进行数据发送，并返回相应结果；如果未连接，则返回 -1 。
    if(isConnected()) {
        return ::sendto(m_sock, buffer, length, flags, to->getAddr(), to->getAddrLen());
    }
    return -1;
}

int Socket::sendTo(const iovec* buffers, size_t length, const Address::ptr to, int flags) {
    if(isConnected()) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        msg.msg_name = to->getAddr();
        msg.msg_namelen = to->getAddrLen();
        return ::sendmsg(m_sock, &msg, flags);
    }
    return -1;
}

int Socket::recv(void* buffer, size_t length, int flags) {
    if(isConnected()) {
        return ::recv(m_sock, buffer, length, flags);
    }
    return -1;
}

int Socket::recv(iovec* buffers, size_t length, int flags) {
    if(isConnected()) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        return ::recvmsg(m_sock, &msg, flags);
    }
    return -1;
}

int Socket::recvFrom(void* buffer, size_t length, Address::ptr from, int flags) {
    if(isConnected()) {
        socklen_t len = from->getAddrLen();
        return ::recvfrom(m_sock, buffer, length, flags, from->getAddr(), &len);
    }
    return -1;
}

int Socket::recvFrom(iovec* buffers, size_t length, Address::ptr from, int flags) {
    if(isConnected()) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        msg.msg_name = from->getAddr();
        msg.msg_namelen = from->getAddrLen();
        return ::recvmsg(m_sock, &msg, flags);
    }
    return -1;
}

Address::ptr Socket::getRemoteAddress() { //获取远程的address，Socket::getRemoteAddress 方法用于获取与当前 Socket 连接的远程地址。
    if(m_remoteAddress) {//如果 m_remoteAddress 成员变量已经保存了远程地址，则直接返回该地址。
        return m_remoteAddress;
    }
//否则，它会根据 Socket 的地址族（m_family）创建一个新的地址对象，并使用 getpeername 系统调用来填充该地址对象的详细信息。
    Address::ptr result;
    switch(m_family) {
        case AF_INET:
            result.reset(new IPv4Address());
            break;
        case AF_INET6:
            result.reset(new IPv6Address());
            break;
        case AF_UNIX:
            result.reset(new UnixAddress());
            break;
        default:
            result.reset(new UnknownAddress(m_family));
            break;
    }
    socklen_t addrlen = result->getAddrLen();
    if(getpeername(m_sock, result->getAddr(), &addrlen)) {//使用 getpeername 系统调用来获取与当前 Socket 连接的远程地址的信息。getpeername 需要三个参数：Socket 描述符（m_sock）、一个指向地址结构的指针（result->getAddr()），以及一个指向地址长度的指针（&addrlen）。addrlen 在调用前被设置为地址结构的大小，getpeername 会根据实际返回的地址信息更新这个长度。
        //SYLAR_LOG_ERROR(g_logger) << "getpeername error sock=" << m_sock
        //    << " errno=" << errno << " errstr=" << strerror(errno);
        return Address::ptr(new UnknownAddress(m_family));
    }
    if(m_family == AF_UNIX) {//如果地址族是 AF_UNIX（Unix 域套接字），则需要对返回的 addrlen 进行特殊处理，因为 Unix 地址结构可能包含比标准 sockaddr_un 更大的数据（例如，包含路径名的 null 终止符）。这里，通过 std::dynamic_pointer_cast 将 result 转换为 UnixAddress::ptr 类型，并调用 setAddrLen 方法来设置正确的地址长度。
        UnixAddress::ptr addr = std::dynamic_pointer_cast<UnixAddress>(result);
        addr->setAddrLen(addrlen);
    }
    m_remoteAddress = result;
    return m_remoteAddress;//最后，将新创建的地址对象保存到 m_remoteAddress 成员变量中，并返回该地址对象。
}

Address::ptr Socket::getLocalAddress() {
    if(m_localAddress) {
        return m_localAddress;
    }

    Address::ptr result;
    switch(m_family) {
        case AF_INET:
            result.reset(new IPv4Address());
            break;
        case AF_INET6:
            result.reset(new IPv6Address());
            break;
        case AF_UNIX:
            result.reset(new UnixAddress());
            break;
        default:
            result.reset(new UnknownAddress(m_family));
            break;
    }
    socklen_t addrlen = result->getAddrLen();
    if(getsockname(m_sock, result->getAddr(), &addrlen)) {
        SYLAR_LOG_ERROR(g_logger) << "getsockname error sock=" << m_sock
            << " errno=" << errno << " errstr=" << strerror(errno);
        return Address::ptr(new UnknownAddress(m_family));
    }
    if(m_family == AF_UNIX) {
        UnixAddress::ptr addr = std::dynamic_pointer_cast<UnixAddress>(result);
        addr->setAddrLen(addrlen);
    }
    m_localAddress = result;
    return m_localAddress;
}

bool Socket::isValid() const {
    return m_sock != -1; //若果sock创建成功返回非负值
}

int Socket::getError() {
    int error = 0;
    socklen_t len = sizeof(error);
    if(!getOption(SOL_SOCKET, SO_ERROR, &error, &len)) {
        error = errno;
    }
    return error;
}

std::ostream& Socket::dump(std::ostream& os) const {
    os << "[Socket sock=" << m_sock
       << " is_connected=" << m_isConnected
       << " family=" << m_family
       << " type=" << m_type
       << " protocol=" << m_protocol;
    if(m_localAddress) {
        os << " local_address=" << m_localAddress->toString();
    }
    if(m_remoteAddress) {
        os << " remote_address=" << m_remoteAddress->toString();
    }
    os << "]";
    return os;
}

std::string Socket::toString() const {
    std::stringstream ss;
    dump(ss);
    return ss.str();
}

bool Socket::cancelRead() {
    return IOManager::GetThis()->cancelEvent(m_sock, sylar::IOManager::READ);
}

bool Socket::cancelWrite() {
    return IOManager::GetThis()->cancelEvent(m_sock, sylar::IOManager::WRITE);
}

bool Socket::cancelAccept() {
    return IOManager::GetThis()->cancelEvent(m_sock, sylar::IOManager::READ);
}

bool Socket::cancelAll() {
    return IOManager::GetThis()->cancelAll(m_sock);
}

void Socket::initSock() {
    int val = 1;
    setOption(SOL_SOCKET, SO_REUSEADDR, val);
    if(m_type == SOCK_STREAM) {
        setOption(IPPROTO_TCP, TCP_NODELAY, val);
    }
}

void Socket::newSock() {
    m_sock = socket(m_family, m_type, m_protocol);
    if(SYLAR_LIKELY(m_sock != -1)) {
        initSock();
    } else {
        SYLAR_LOG_ERROR(g_logger) << "socket(" << m_family
            << ", " << m_type << ", " << m_protocol << ") errno="
            << errno << " errstr=" << strerror(errno);
    }
}

namespace {

struct _SSLInit {
    _SSLInit() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
};

static _SSLInit s_init;

}

SSLSocket::SSLSocket(int family, int type, int protocol)
    :Socket(family, type, protocol) {
}

Socket::ptr SSLSocket::accept() {
    SSLSocket::ptr sock(new SSLSocket(m_family, m_type, m_protocol));
    int newsock = ::accept(m_sock, nullptr, nullptr);
    if(newsock == -1) {
        SYLAR_LOG_ERROR(g_logger) << "accept(" << m_sock << ") errno="
            << errno << " errstr=" << strerror(errno);
        return nullptr;
    }
    sock->m_ctx = m_ctx;
    if(sock->init(newsock)) {
        return sock;
    }
    return nullptr;
}

bool SSLSocket::bind(const Address::ptr addr) {
    return Socket::bind(addr);
}

bool SSLSocket::connect(const Address::ptr addr, uint64_t timeout_ms) {
    bool v = Socket::connect(addr, timeout_ms);
    if(v) {
        m_ctx.reset(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
        m_ssl.reset(SSL_new(m_ctx.get()),  SSL_free);
        SSL_set_fd(m_ssl.get(), m_sock);
        v = (SSL_connect(m_ssl.get()) == 1);
    }
    return v;
}

bool SSLSocket::listen(int backlog) {
    return Socket::listen(backlog);
}

bool SSLSocket::close() {
    return Socket::close();
}

int SSLSocket::send(const void* buffer, size_t length, int flags) {
    if(m_ssl) {
        return SSL_write(m_ssl.get(), buffer, length);
    }
    return -1;
}

int SSLSocket::send(const iovec* buffers, size_t length, int flags) {
    if(!m_ssl) {
        return -1;
    }
    int total = 0;
    for(size_t i = 0; i < length; ++i) {
        int tmp = SSL_write(m_ssl.get(), buffers[i].iov_base, buffers[i].iov_len);
        if(tmp <= 0) {
            return tmp;
        }
        total += tmp;
        if(tmp != (int)buffers[i].iov_len) {
            break;
        }
    }
    return total;
}

int SSLSocket::sendTo(const void* buffer, size_t length, const Address::ptr to, int flags) {
    SYLAR_ASSERT(false);
    return -1;
}

int SSLSocket::sendTo(const iovec* buffers, size_t length, const Address::ptr to, int flags) {
    SYLAR_ASSERT(false);
    return -1;
}

int SSLSocket::recv(void* buffer, size_t length, int flags) {
    if(m_ssl) {
        return SSL_read(m_ssl.get(), buffer, length);
    }
    return -1;
}

int SSLSocket::recv(iovec* buffers, size_t length, int flags) {
    if(!m_ssl) {
        return -1;
    }
    int total = 0;
    for(size_t i = 0; i < length; ++i) {
        int tmp = SSL_read(m_ssl.get(), buffers[i].iov_base, buffers[i].iov_len);
        if(tmp <= 0) {
            return tmp;
        }
        total += tmp;
        if(tmp != (int)buffers[i].iov_len) {
            break;
        }
    }
    return total;
}

int SSLSocket::recvFrom(void* buffer, size_t length, Address::ptr from, int flags) {
    SYLAR_ASSERT(false);
    return -1;
}

int SSLSocket::recvFrom(iovec* buffers, size_t length, Address::ptr from, int flags) {
    SYLAR_ASSERT(false);
    return -1;
}

bool SSLSocket::init(int sock) {
    bool v = Socket::init(sock);
    if(v) {
        m_ssl.reset(SSL_new(m_ctx.get()),  SSL_free);
        SSL_set_fd(m_ssl.get(), m_sock);
        v = (SSL_accept(m_ssl.get()) == 1);
    }
    return v;
}

bool SSLSocket::loadCertificates(const std::string& cert_file, const std::string& key_file) {
    m_ctx.reset(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free);
    if(SSL_CTX_use_certificate_chain_file(m_ctx.get(), cert_file.c_str()) != 1) {
        SYLAR_LOG_ERROR(g_logger) << "SSL_CTX_use_certificate_chain_file("
            << cert_file << ") error";
        return false;
    }
    if(SSL_CTX_use_PrivateKey_file(m_ctx.get(), key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        SYLAR_LOG_ERROR(g_logger) << "SSL_CTX_use_PrivateKey_file("
            << key_file << ") error";
        return false;
    }
    if(SSL_CTX_check_private_key(m_ctx.get()) != 1) {
        SYLAR_LOG_ERROR(g_logger) << "SSL_CTX_check_private_key cert_file="
            << cert_file << " key_file=" << key_file;
        return false;
    }
    return true;
}

SSLSocket::ptr SSLSocket::CreateTCP(sylar::Address::ptr address) {
    SSLSocket::ptr sock(new SSLSocket(address->getFamily(), TCP, 0));
    return sock;
}

SSLSocket::ptr SSLSocket::CreateTCPSocket() {
    SSLSocket::ptr sock(new SSLSocket(IPv4, TCP, 0));
    return sock;
}

SSLSocket::ptr SSLSocket::CreateTCPSocket6() {
    SSLSocket::ptr sock(new SSLSocket(IPv6, TCP, 0));
    return sock;
}

std::ostream& SSLSocket::dump(std::ostream& os) const {
    os << "[SSLSocket sock=" << m_sock
       << " is_connected=" << m_isConnected
       << " family=" << m_family
       << " type=" << m_type
       << " protocol=" << m_protocol;
    if(m_localAddress) {
        os << " local_address=" << m_localAddress->toString();
    }
    if(m_remoteAddress) {
        os << " remote_address=" << m_remoteAddress->toString();
    }
    os << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, const Socket& sock) {
    return sock.dump(os);
}

}
