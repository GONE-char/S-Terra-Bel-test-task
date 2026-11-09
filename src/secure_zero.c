#include "secure_zero.h"

void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len > 0) {
        *p = 0;
        ++p;
        --len;
    }
}
