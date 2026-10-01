#ifndef FPC_NATIVE_PROTOCOL_HPP
#define FPC_NATIVE_PROTOCOL_HPP
#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>
namespace fpc {
struct WireEvent {
    uint32_t code{}, length{}, result{};
    std::vector<unsigned char> body;
};
struct CaptureHeader { uint32_t tag, acquisition_loop, send_counter; };
inline CaptureHeader capture_header(const unsigned char* data,size_t size) {
    if(!data || (size!=12+9856 && size!=12+2*9856))
        throw std::runtime_error("invalid FPC capture length");
    auto word=[&](size_t offset){return uint32_t(data[offset])<<24|uint32_t(data[offset+1])<<16|uint32_t(data[offset+2])<<8|uint32_t(data[offset+3]);};
    return {word(0),word(4),word(8)};
}
class EventFramer {
    std::vector<unsigned char> pending;
    static uint32_t word(const unsigned char *bytes) {
        return uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 |
               bytes[3];
    }

  public:
    static constexpr size_t maximum = 65536;
    void feed(const void *data, size_t size) {
        if (size > 2 * maximum - pending.size())
            throw std::runtime_error("FPC receive limit");
        auto bytes = static_cast<const unsigned char *>(data);
        if (size)
            pending.insert(pending.end(), bytes, bytes + size);
    }
    std::optional<WireEvent> next() {
        if (pending.size() < 12)
            return std::nullopt;
        auto length = word(pending.data() + 4);
        if (length < 12 || length > maximum)
            throw std::runtime_error("invalid FPC frame length");
        if (pending.size() < length)
            return std::nullopt;
        WireEvent event{word(pending.data()),
                        length,
                        word(pending.data() + 8),
                        {pending.begin() + 12, pending.begin() + length}};
        pending.erase(pending.begin(), pending.begin() + length);
        return event;
    }
};
} // namespace fpc
#endif
