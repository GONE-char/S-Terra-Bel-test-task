#include "hmac.h"

#include <cstring>

#include "secure_zero.h"

// HMAC-SHA256 по RFC 2104:
//   K'  = (ключ длиннее 64 байт) ? SHA256(key) : key, дополненный нулями до 64
//   HMAC = SHA256( (K' ^ 0x5c*64) || SHA256( (K' ^ 0x36*64) || message ) )
Digest hmac_sha256(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len) {
    uint8_t k[64] = {0};
    if (key_len > sizeof(k)) {
        Digest hashed = sha256(key, key_len);
        std::memcpy(k, hashed.data(), hashed.size());
        secure_zero(hashed.data(), hashed.size());
    } else if (key_len > 0) {
        std::memcpy(k, key, key_len);
    }

    uint8_t pad[64];

    Sha256 inner;
    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
    }
    inner.update(pad, sizeof(pad));
    inner.update(data, data_len);
    Digest inner_hash = inner.finish();

    Sha256 outer;
    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }
    outer.update(pad, sizeof(pad));
    outer.update(inner_hash.data(), inner_hash.size());
    Digest out = outer.finish();

    // Затираем промежуточный ключевой материал
    secure_zero(k, sizeof(k));
    secure_zero(pad, sizeof(pad));
    secure_zero(inner_hash.data(), inner_hash.size());
    return out;
}
