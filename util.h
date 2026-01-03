#ifndef CRC_H
#define CRC_H

#include <stdint.h>
#include <stddef.h>

#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>



void crc32_init(void);
uint32_t crc32(const uint8_t *buf, size_t len);

int compute_sha256_file(const char *path, uint8_t out_hash[SHA256_DIGEST_LENGTH]);
void sha256_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH], char hex[65]);
#endif
