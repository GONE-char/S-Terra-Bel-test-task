#ifndef COMMON_H
#define COMMON_H

#include <cstddef>
#include <cstdint>

#include <netinet/in.h>

#include "protocol.h"
#include "sha256.h"

// Общий секрет — 32-байтовый SHA-256.
using Secret = Digest;

// Энтропия: std::random_device (на Linux читает /dev/urandom).
proto::Bytes random_bytes(size_t n);
uint32_t random_exchange_id();

// secret = SHA256(client_random || server_random || nonce || exchange_id),
// где exchange_id — 4 байта в big-endian (network order), как в пакете.
Secret compute_secret(const proto::Bytes& client_random,
                      const proto::Bytes& server_random,
                      const proto::Bytes& nonce,
                      uint32_t exchange_id);

// HMAC-SHA256(secret, type || exchange_id || client_random || server_random || nonce)
// type — 1 байт, exchange_id — 4 байта big-endian. Порядок одинаковый у обеих сторон.
Secret confirm_hmac(const Secret& secret, uint8_t type, uint32_t exchange_id,
                    const proto::Bytes& client_random,
                    const proto::Bytes& server_random,
                    const proto::Bytes& nonce);

// Затирание секретного материала через pure-C secure_zero.
void wipe(proto::Bytes& b);
void wipe(Secret& s);

// Сравнение без раннего выхода (для HMAC).
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

// Совпадают ли адрес и порт отправителя.
bool same_endpoint(const sockaddr_in& a, const sockaddr_in& b);

// SO_RCVTIMEO на сокете, таймаут в миллисекундах.
bool set_recv_timeout(int fd, int ms);

// Разбор номера порта (1..65535).
bool parse_port(const char* s, uint16_t& out);

#endif // COMMON_H
