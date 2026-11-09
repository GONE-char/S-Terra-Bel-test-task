#ifndef SHA256_H
#define SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>

// Собственная реализация SHA-256 по FIPS 180-4.
// Сторонние библиотеки не используются.

using Digest = std::array<uint8_t, 32>;

class Sha256 {
public:
    Sha256();

    // Добавляет порцию данных в хеш.
    void update(const uint8_t* data, size_t len);

    // Выполняет дополнение (padding) и возвращает 32-байтовый хеш.
    Digest finish();

private:
    void process_block(const uint8_t* block);

    uint32_t h_[8];       // текущее состояние хеша
    uint64_t total_ = 0;  // сколько байт данных подано в update
    uint8_t buf_[64];     // незаполненный блок
    size_t buf_len_ = 0;  // занято байт в buf_
};

// Одношаговый вариант: SHA-256 от data[0..len).
Digest sha256(const uint8_t* data, size_t len);

#endif // SHA256_H
