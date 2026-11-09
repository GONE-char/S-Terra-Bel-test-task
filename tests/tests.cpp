// Минимальные unit-тесты без сторонних фреймворков
// Запуск: make test
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#include "common.h"
#include "hmac.h"
#include "protocol.h"
#include "secure_zero.h"
#include "sha256.h"

using namespace proto;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": "      \
                      << #cond << std::endl;                                 \
        }                                                                    \
    } while (0)

static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s += d[p[i] >> 4];
        s += d[p[i] & 0x0F];
    }
    return s;
}

template <size_t N>
static std::string hex(const std::array<uint8_t, N>& a) {
    return hex(a.data(), N);
}

// 1. SHA-256: эталонные векторы FIPS 180-4
static void test_sha256_vectors() {
    CHECK(hex(sha256(reinterpret_cast<const uint8_t*>(""), 0)) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hex(sha256(reinterpret_cast<const uint8_t*>("abc"), 3)) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// 2. HMAC-SHA256: эталонные векторы RFC 4231 (test case 1 и 2)
static void test_hmac_vectors() {
    const uint8_t key1[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const std::string data1 = "Hi There";
    CHECK(hex(hmac_sha256(key1, sizeof(key1),
                          reinterpret_cast<const uint8_t*>(data1.data()), data1.size())) ==
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    const std::string key2 = "Jefe";
    const std::string data2 = "what do ya want for nothing?";
    CHECK(hex(hmac_sha256(reinterpret_cast<const uint8_t*>(key2.data()), key2.size(),
                          reinterpret_cast<const uint8_t*>(data2.data()), data2.size())) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// 3. Разбор заголовка: сборка/разбор + точный порядок байт в пакете
static void test_header_roundtrip() {
    Bytes payload(kRandomSize);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i);
    }
    const Bytes pkt = build_packet(INIT, 0x01020304u, payload);

    CHECK(pkt.size() == kHeaderSize + kRandomSize);
    CHECK(pkt[0] == 0x4B && pkt[1] == 0x45 && pkt[2] == 0x59 && pkt[3] == 0x31); // KEY1
    CHECK(pkt[4] == 1 && pkt[5] == INIT && pkt[6] == 0 && pkt[7] == 0);
    CHECK(pkt[8] == 1 && pkt[9] == 2 && pkt[10] == 3 && pkt[11] == 4); // id big-endian

    Header hdr;
    Bytes parsed;
    std::string err;
    CHECK(parse_packet(pkt.data(), pkt.size(), hdr, parsed, err));
    CHECK(hdr.type == INIT);
    CHECK(hdr.exchange_id == 0x01020304u);
    CHECK(parsed == payload);
}

// 4. Обрезанный пакет: короче заголовка и короче полезной нагрузки
static void test_truncated_packet() {
    Bytes payload(kRandomSize, 0xAA);
    const Bytes pkt = build_packet(INIT, 7u, payload);
    Header hdr;
    Bytes parsed;
    std::string err;

    CHECK(!parse_packet(pkt.data(), 5, hdr, parsed, err));   // нет полного заголовка
    CHECK(!parse_packet(pkt.data(), kHeaderSize, hdr, parsed, err)); // нет payload
    CHECK(!parse_packet(pkt.data(), pkt.size() - 1, hdr, parsed, err)); // обрезан на байт
}

// 5. Неверный magic / версия
static void test_bad_magic_and_version() {
    Bytes payload(kRandomSize, 0x11);
    Bytes pkt = build_packet(INIT, 7u, payload);
    Header hdr;
    Bytes parsed;
    std::string err;

    Bytes bad = pkt;
    bad[0] ^= 0xFF;
    CHECK(!parse_packet(bad.data(), bad.size(), hdr, parsed, err));

    bad = pkt;
    bad[4] = 2; // версия
    CHECK(!parse_packet(bad.data(), bad.size(), hdr, parsed, err));
}

// 6. Неизвестный type
static void test_unknown_type() {
    Bytes payload(kRandomSize, 0x22);
    Bytes pkt = build_packet(INIT, 7u, payload);
    pkt[5] = 9;
    Header hdr;
    Bytes parsed;
    std::string err;
    CHECK(!parse_packet(pkt.data(), pkt.size(), hdr, parsed, err));
}

// 7. Совпадение секрета и HMAC у обеих сторон
//    Эталонные значения независимо посчитаны в Python (hashlib/hmac)
//    для client_random=00..1f, server_random=20..3f, nonce=40..5f,
//    exchange_id=0x01020304 (big-endian)
static void test_secret_and_hmac_match() {
    Bytes cr(kRandomSize), sr(kRandomSize), nonce(kNonceSize);
    for (size_t i = 0; i < kRandomSize; ++i) {
        cr[i] = static_cast<uint8_t>(i);          // 00..1f
        sr[i] = static_cast<uint8_t>(i + 32);     // 20..3f
        nonce[i] = static_cast<uint8_t>(i + 64);  // 40..5f
    }
    const uint32_t id = 0x01020304u;

    // "Клиент" и "сервер" считают независимо, на одинаковых входных данных
    const Secret secret_client = compute_secret(cr, sr, nonce, id);
    const Secret secret_server = compute_secret(cr, sr, nonce, id);
    CHECK(secret_client == secret_server);
    CHECK(hex(secret_client) ==
          "c6996db273ef549460d095d4d1645e292235cdddbac49c5c5382ab33a9ea141d");

    const Secret confirm = confirm_hmac(secret_client, CONFIRM, id, cr, sr, nonce);
    const Secret confirm_server = confirm_hmac(secret_server, CONFIRM, id, cr, sr, nonce);
    CHECK(confirm == confirm_server);
    CHECK(hex(confirm) ==
          "8c4c39a059b9d74bf5488afcf3790dbf96053c3efe6ad9d8a9ffa4de8eb94d55");

    const Secret ack = confirm_hmac(secret_client, CONFIRM_ACK, id, cr, sr, nonce);
    CHECK(hex(ack) ==
          "d12d21b80e50cc04be7f7baebd6f67b0e5c2902e92e5db699a6b443e02ce8220");
    CHECK(confirm != ack); // разный type => разный HMAC

    // Другой exchange_id => другой секрет (защита от перепутывания сессий)
    const Secret other = compute_secret(cr, sr, nonce, id + 1);
    CHECK(other != secret_client);
}

// 8. secure_zero реально затирает память
static void test_secure_zero() {
    uint8_t buf[16];
    std::memset(buf, 0xAA, sizeof(buf));
    secure_zero(buf, sizeof(buf));
    for (uint8_t b : buf) {
        CHECK(b == 0);
    }
}

int main() {
    test_sha256_vectors();
    test_hmac_vectors();
    test_header_roundtrip();
    test_truncated_packet();
    test_bad_magic_and_version();
    test_unknown_type();
    test_secret_and_hmac_match();
    test_secure_zero();

    if (g_failures != 0) {
        std::cerr << g_failures << " of " << g_checks << " checks FAILED" << std::endl;
        return 1;
    }
    std::cout << "all tests passed (" << g_checks << " checks)" << std::endl;
    return 0;
}
