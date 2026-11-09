#include "common.h"

#include <cstdlib>
#include <random>

#include <sys/socket.h>
#include <sys/time.h>

#include "hmac.h"
#include "secure_zero.h"

proto::Bytes random_bytes(size_t n) {
    std::random_device rd; // на Linux /dev/urandom
    proto::Bytes out(n);
    for (auto& b : out) {
        b = static_cast<uint8_t>(rd() & 0xFFu);
    }
    return out;
}

uint32_t random_exchange_id() {
    const proto::Bytes b = random_bytes(4);
    return proto::read_u32_be(b.data());
}

Secret compute_secret(const proto::Bytes& client_random,
                      const proto::Bytes& server_random,
                      const proto::Bytes& nonce,
                      uint32_t exchange_id) {
    proto::Bytes msg;
    msg.reserve(client_random.size() + server_random.size() + nonce.size() + 4);
    msg.insert(msg.end(), client_random.begin(), client_random.end());
    msg.insert(msg.end(), server_random.begin(), server_random.end());
    msg.insert(msg.end(), nonce.begin(), nonce.end());
    proto::append_u32_be(msg, exchange_id); // 4 байта big-endian, как в пакете
    Secret out = sha256(msg.data(), msg.size());
    wipe(msg);
    return out;
}

Secret confirm_hmac(const Secret& secret, uint8_t type, uint32_t exchange_id,
                    const proto::Bytes& client_random,
                    const proto::Bytes& server_random,
                    const proto::Bytes& nonce) {
    proto::Bytes msg;
    msg.reserve(1 + 4 + client_random.size() + server_random.size() + nonce.size());
    msg.push_back(type);                    // type: 1 байт
    proto::append_u32_be(msg, exchange_id); // exchange_id: 4 байта big-endian
    msg.insert(msg.end(), client_random.begin(), client_random.end());
    msg.insert(msg.end(), server_random.begin(), server_random.end());
    msg.insert(msg.end(), nonce.begin(), nonce.end());
    Secret out = hmac_sha256(secret.data(), secret.size(), msg.data(), msg.size());
    wipe(msg);
    return out;
}

void wipe(proto::Bytes& b) {
    if (!b.empty()) {
        secure_zero(b.data(), b.size());
    }
    b.clear();
}

void wipe(Secret& s) {
    secure_zero(s.data(), s.size());
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool same_endpoint(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_family == b.sin_family &&
           a.sin_port == b.sin_port &&
           a.sin_addr.s_addr == b.sin_addr.s_addr;
}

bool set_recv_timeout(int fd, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = static_cast<long>(ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

bool parse_port(const char* s, uint16_t& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 1 || v > 65535) {
        return false;
    }
    out = static_cast<uint16_t>(v);
    return true;
}
