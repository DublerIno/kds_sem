#include "util.h"


//variable to hold the crc32 table
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

void crc32_init(void)
{
    if (crc32_initialized)
        return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++){
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }

    crc32_initialized = 1;
}

uint32_t crc32(const uint8_t *buf, size_t len)
{
    uint32_t c = 0xFFFFFFFFU;

    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);

    return c ^ 0xFFFFFFFFU;
}   


// Computes SHA256 of a file.
int compute_sha256_file(const char *path, uint8_t out_hash[SHA256_DIGEST_LENGTH]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    uint8_t buf[4096];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }

    if (ferror(f)) {
        perror("fread");
        fclose(f);
        return -1;
    }

    SHA256_Final(out_hash, &ctx);
    fclose(f);
    return 0;
}

//
void sha256_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH], char hex[65]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[64] = '\0';
}
