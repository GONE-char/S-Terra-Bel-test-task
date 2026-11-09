#ifndef HMAC_H
#define HMAC_H

#include <cstddef>
#include <cstdint>

#include "sha256.h"

// HMAC-SHA256 по RFC 2104: размер блока 64 байта, результат 32 байта.
// key_len может быть любым (ключ длиннее 64 байт сначала хешируется).
Digest hmac_sha256(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len);

#endif // HMAC_H
