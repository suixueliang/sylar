/**
 * @file endian.h
 * @brief 字节序操作函数(大端/小端)
 * @author sylar.yin
 * @email 564628276@qq.com
 * @date 2019-06-01
 * @copyright Copyright (c) 2019年 sylar.yin All rights reserved (www.sylar.top)
 */
#ifndef __SYLAR_ENDIAN_H__
#define __SYLAR_ENDIAN_H__

#define SYLAR_LITTLE_ENDIAN 1
#define SYLAR_BIG_ENDIAN 2

#include <byteswap.h>
#include <stdint.h>

namespace sylar {

/**
 * @brief 8字节类型的字节序转化
 */
"""
这段代码定义了一个模板函数 byteswap 。它接受一个类型为 T 的参数 value 。通过 std::enable_if 条件判断，只有当 T 的大小等于 uint64_t 的大小时，该函数才有效。函数的功能是返回通过 bswap_64 函数对传入的 value 进行转换后的结果，并将其强制转换为 T 类型。
"""
template<class T>
typename std::enable_if<sizeof(T) == sizeof(uint64_t), T>::type //条件判断机制
byteswap(T value) {   //将一个 64 位整数从大端字节序转换为小端字节序或从小端字节序转换为大端字节序。
    return (T)bswap_64((uint64_t)value);
}

/**
 * @brief 4字节类型的字节序转化
 */
template<class T>
typename std::enable_if<sizeof(T) == sizeof(uint32_t), T>::type
byteswap(T value) {
    return (T)bswap_32((uint32_t)value);
}

/**
 * @brief 2字节类型的字节序转化
 */
template<class T>
typename std::enable_if<sizeof(T) == sizeof(uint16_t), T>::type
byteswap(T value) {
    return (T)bswap_16((uint16_t)value);
}
//检查系统的字节序是否为大端（BIG_ENDIAN）。如果是，则定义 SYLAR_BYTE_ORDER 为 SYLAR_BIG_ENDIAN；否则，定义为 SYLAR_LITTLE_ENDIAN
#if BYTE_ORDER == BIG_ENDIAN
#define SYLAR_BYTE_ORDER SYLAR_BIG_ENDIAN
#else
#define SYLAR_BYTE_ORDER SYLAR_LITTLE_ENDIAN
#endif
//根据前面定义的 SYLAR_BYTE_ORDER 进行条件编译。如果系统是大端字节序，则会执行这部分代码。
#if SYLAR_BYTE_ORDER == SYLAR_BIG_ENDIAN

/**
 * @brief 只在小端机器上执行byteswap, 在大端机器上什么都不做
 */
template<class T>
T byteswapOnLittleEndian(T t) {
    return t;
}

/**
 * @brief 只在大端机器上执行byteswap, 在小端机器上什么都不做
 */
template<class T>
T byteswapOnBigEndian(T t) {
    return byteswap(t);
}
#else

/**
 * @brief 只在小端机器上执行byteswap, 在大端机器上什么都不做
 */
template<class T>
T byteswapOnLittleEndian(T t) {
    return byteswap(t);
}

/**
 * @brief 只在大端机器上执行byteswap, 在小端机器上什么都不做
 */
template<class T>
T byteswapOnBigEndian(T t) {
    return t;
}
#endif

}

#endif
