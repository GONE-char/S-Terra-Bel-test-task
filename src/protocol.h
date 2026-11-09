#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proto {

// Одна UDP-датаграмма = одно сообщение: заголовок 12 байт + полезная нагрузка.
// Все многобайтовые целые — в network byte order (big-endian).
constexpr uint32_t kMagic = 0x4B455931u; // байты 'K' 'E' 'Y' '1'
constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 12;
constexpr size_t kMaxPayload = 2048;
constexpr size_t kRandomSize = 32; // client_random / server_random
constexpr size_t kNonceSize = 32;  // nonce
constexpr size_t kHmacSize = 32;   // HMAC-SHA256

enum MsgType : uint8_t {
    INIT = 1,
    INIT_ACK = 2,
    CONFIRM = 3,
    CONFIRM_ACK = 4,
};

using Bytes = std::vector<uint8_t>;

struct Header {
    uint8_t type = 0;
    uint32_t exchange_id = 0; // в host order после разбора
};

// Ожидаемый размер полезной нагрузки для типа; -1, если тип неизвестен.
int expected_payload(uint8_t type);

// Собирает пакет: заголовок + payload.
Bytes build_packet(uint8_t type, uint32_t exchange_id, const Bytes& payload);

// Разбирает и полностью проверяет пакет (magic, версия, flags/reserved,
// тип, длина полезной нагрузки). При ошибке возвращает false и пишет
// причину в err; hdr и payload не изменяются.
bool parse_packet(const uint8_t* data, size_t len,
                  Header& hdr, Bytes& payload, std::string& err);

// Big-endian (network order) helpers для exchange_id.
void append_u32_be(Bytes& out, uint32_t value);
uint32_t read_u32_be(const uint8_t* p);

} // namespace proto

#endif // PROTOCOL_H
