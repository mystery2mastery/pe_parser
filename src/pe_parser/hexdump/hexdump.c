#include <stdio.h>

#include <stdio.h>
#include "hexdump.h"


void hexdump(const void* data, size_t size, size_t start_address) {
    const unsigned char* p = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx:", start_address + i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size)
                printf(" %02x", p[i + j]);
            else
                printf("   ");

            if (j % 8 == 7)
                printf(" ");
        }

        printf(" ");

        for (j = 0; j < 16 && i + j < size; ++j) {
            char c = p[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        printf("\n");
    }
}