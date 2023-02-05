#include <stdint.h>
#include <stdio.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

void test_encrypt_ecb(void)
{
    uint8_t key[] = {0x3c, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    struct AES_ctx ctx;

    for (uint8_t i = 0; i < 16; ++i)
    {
        printf("%d", in[i]);
    }
    printf("\n");

    AES_init_ctx(&ctx, key);

    AES_ECB_encrypt(&ctx, in);
    for (uint8_t i = 0; i < 16; ++i)
    {
        printf("%d", in[i]);
    }
    printf("\n");

    AES_ECB_decrypt(&ctx, in);
    for (uint8_t i = 0; i < 16; ++i)
    {
        printf("%d", in[i]);
    }
    printf("\n");
}

int main()
{
    test_encrypt_ecb();
    return 0;
}