#include "protocol.h"

namespace proto {

int expected_payload(uint8_t type) {
    switch (type) {
    case INIT:       return static_cast<int>(kRandomSize);               // 32
    case INIT_ACK:   return static_cast<int>(kRandomSize + kNonceSize);  // 64
    case CONFIRM:    return static_cast<int>(kHmacSize);                 // 32
    case CONFIRM_ACK:return static_cast<int>(kHmacSize);                 // 32
    default:         return -1;
    }
}

void append_u32_be(Bytes& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           (static_cast<uint32_t>(p[3]));
}

Bytes build_packet(uint8_t type, uint32_t exchange_id, const Bytes& payload) {
    Bytes out;
    out.reserve(kHeaderSize + payload.size());
    append_u32_be(out, kMagic);      // magic: 4 байта 'K' 'E' 'Y' '1'
    out.push_back(kVersion);         // version
    out.push_back(type);             // type
    out.push_back(0);                // flags
    out.push_back(0);                // reserved
    append_u32_be(out, exchange_id); // exchange_id, network order
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool parse_packet(const uint8_t* data, size_t len,
                  Header& hdr, Bytes& payload, std::string& err) {
    if (len < kHeaderSize) {
        err = "truncated packet: header shorter than 12 bytes";
        return false;
    }
    if (read_u32_be(data) != kMagic) {
        err = "bad magic";
        return false;
    }
    if (data[4] != kVersion) {
        err = "unsupported version";
        return false;
    }
    if (data[6] != 0 || data[7] != 0) {
        err = "flags/reserved must be zero";
        return false;
    }
    const uint8_t type = data[5];
    const int expected = expected_payload(type);
    if (expected < 0) {
        err = "unknown message type";
        return false;
    }
    const size_t payload_len = len - kHeaderSize;
    if (payload_len > kMaxPayload) {
        err = "payload too large";
        return false;
    }
    if (payload_len != static_cast<size_t>(expected)) {
        err = "payload length mismatch";
        return false;
    }
    hdr.type = type;
    hdr.exchange_id = read_u32_be(data + 8);
    payload.assign(data + kHeaderSize, data + len);
    return true;
}

} // namespace proto
