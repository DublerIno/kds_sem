#ifndef CRC_H
#define CRC_H

#include <stdint.h>
#include <stddef.h>

#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>

//info packet
#define INFO_HDR 12
#define INFO_ID  0u   // fixed ID for INFO packet
#define ACK_START 1u // Control message StartandWait ID for START/STOP



void crc32_init(void);
uint32_t crc32(const uint8_t *buf, size_t len);

int compute_sha256_file(const char *path, uint8_t out_hash[SHA256_DIGEST_LENGTH]);
void sha256_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH], char hex[65]);
#endif
