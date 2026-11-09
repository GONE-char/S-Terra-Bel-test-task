#ifndef SECURE_ZERO_H
#define SECURE_ZERO_H

/* Чистый C (C99), без C++-зависимостей. Подключается и из C++, и из C. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Гарантированно затирает len байт по адресу ptr нулями.
   Запись идёт через volatile-указатель, поэтому компилятор
   не имеет права выбросить её как "мёртвую". */
void secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_ZERO_H */
