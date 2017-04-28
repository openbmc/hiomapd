#pragma once

#include <endian.h>
#include <stdint.h>

namespace endian
{
namespace details
{

template <typename T>
struct convert
{
    static T toVpnor(T) = delete;
};

template<> struct convert<uint16_t>
{
    // Convert to big endian, as needed by the virtual pnor
    static uint16_t toVpnor(uint16_t i) { return htobe16(i); };
};

template<> struct convert<uint32_t>
{
    // Convert to big endian, as needed by the virtual pnor
    static uint32_t toVpnor(uint32_t i) { return htobe32(i); };
};

} // namespace details

template<typename T> T toVpnor(T i)
{
    return details::convert<T>::toVpnor(i);
}

}
