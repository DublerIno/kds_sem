// Usage: ./receiver <listen_data_port> <derper_ip> <derper_ack_port>
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>         // close()
#include <sys/socket.h>     // socket(), bind(), recvfrom(), sendto()
#include <netinet/in.h>     // sockaddr_in
#include <arpa/inet.h>      // inet_pton(), ntohl()

#include "util.h"

#define PACKET_MAX 1024
#define DATA_HDR   12

#define INFO_ID  0u   // fixed ID for INFO packet
#define ACK_START 1u // Control message StartandWait ID for START/STOP


static int send_reply(int s, const struct sockaddr_in *to, const char *msg) {
    ssize_t n = sendto(
        s, msg, strlen(msg), 0,
        (const struct sockaddr *)to, (socklen_t)sizeof(*to)
    );
    return (n < 0) ? -1 : 0;
}
static int send_reply_ctrl(int s, const struct sockaddr_in *to, uint32_t ctrl_id) {
    char reply[64];
    snprintf(reply, sizeof(reply), "ACK %u", ctrl_id);
    return send_reply(s, to, reply);
}

static void parse_info_payload(
    const char *payload,
    size_t payload_len,
    char *out_filename,
    size_t out_filename_cap,
    uint32_t *out_expected_size,
    char out_expected_hash_hex[65]
);


static int receive_info_and_reply(
    int s,
    const uint8_t *buf,
    size_t nbytes,
    const struct sockaddr_in *ack_addr,
    char *out_filename,
    size_t out_filename_cap,
    uint32_t *out_expected_size,
    char out_expected_hash_hex[65]
);

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <listen_data_port> <derper_ip> <derper_ack_port>\n", argv[0]);
        return 1;
    }

    int listen_port   = atoi(argv[1]);   // where receiver listens for DATA/control
    const char *derper_ip = argv[2];     // NetDerper host (ACK ingress host)
    int derper_ack_port = atoi(argv[3]); // NetDerper ACK SourcePort (e.g., 14001)

    printf("receiver started (listen=%d, ack_to=%s:%d)\n", listen_port, derper_ip, derper_ack_port);

    // Initialize CRC table
    crc32_init();

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return 1;
    }

    // Bind receiver socket to DATA listen port
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port   = htons((unsigned short)listen_port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&local, (socklen_t)sizeof(local)) < 0) {
        fprintf(stderr, "bind(%d) failed: %s\n", listen_port, strerror(errno));
        close(s);
        return 1;
    }

    // Address to send ACK/NACK 
    struct sockaddr_in ack_addr;
    memset(&ack_addr, 0, sizeof(ack_addr));
    ack_addr.sin_family = AF_INET;
    ack_addr.sin_port   = htons((unsigned short)derper_ack_port);
    if (inet_pton(AF_INET, derper_ip, &ack_addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton(derper_ip) failed for '%s'\n", derper_ip);
        close(s);
        return 1;
    }

    //INFO 
    char filename[256] = "received.bin";
    uint32_t expected_size = 0;
    char expected_hash_hex[65] = {0}; // 64 hex 
    FILE *out = NULL;

    uint32_t expected_off = 0; // stop-and-wait: next expected file offset

    uint8_t buf[PACKET_MAX];

    struct sockaddr_in peer;
    socklen_t peerlen;
    
    
    for (;;) {
        peerlen = (socklen_t)sizeof(peer);
        int n = (int)recvfrom(s, buf, (size_t)PACKET_MAX, 0, (struct sockaddr *)&peer, &peerlen);
        if (n <= 0) {
            // recvfrom error or empty packet; continue
            continue;
        }

        int handled = receive_info_and_reply(
        s, buf, (size_t)n, &ack_addr,
        filename, sizeof(filename),
        &expected_size, expected_hash_hex
        );
        if (handled != 0) {
            if (handled < 0) break; // fatal
            continue;               // INFO handled (ACK/NACK sent)
        }

        // Check for control message
        if (n < DATA_HDR || memcmp(buf, "DATA", 4) != 0) {
            char txt[PACKET_MAX + 1];
            memcpy(txt, buf, (size_t)n);
            txt[n] = '\0';

            if (!strcmp(txt, "START")) {
                out = fopen(filename, "wb+");
                if (!out) {
                    fprintf(stderr, "fopen('%s') failed: %s\n", filename, strerror(errno));
                    break;
                }
                expected_off = 0;
                printf("Receiving %s (%u bytes)\n", filename, (unsigned)expected_size);
                send_reply_ctrl(s, &ack_addr, ACK_START);
            } else if (!strcmp(txt, "STOP")) {
                printf("STOP\n");
                send_reply_ctrl(s, &ack_addr, ACK_START);
                break;
            }

            continue;
        }

        // DATA packet parsing
        //"DATA" + offset + crc32 + payload
        uint32_t netoff, netcrc;
        memcpy(&netoff, buf + 4, 4);
        memcpy(&netcrc, buf + 8, 4);

        uint32_t off = ntohl(netoff);
        uint32_t recv_crc = ntohl(netcrc);

        int payload_len = n - DATA_HDR;
        uint8_t *payload = buf + DATA_HDR;

        uint32_t calc_crc = crc32(payload, (size_t)payload_len);

        char reply[64];

        // CRC error -> NACK (request retransmission)
        if (calc_crc != recv_crc) {
            snprintf(reply, sizeof(reply), "NACK %u", off);
            if (send_reply(s, &ack_addr, reply) < 0) {
                fprintf(stderr, "sendto(NACK) failed: %s\n", strerror(errno));
                break;
            }
            printf("NACK %u\n", off);
            continue;
        }

        // No output file opened -> just ACK and continue
        if (!out) {
            snprintf(reply, sizeof(reply), "ACK %u", off);
            send_reply(s, &ack_addr, reply);
            continue;
        }

        // Duplicate handling (Stop-and-Wait requirement):
        // - If off < expected_off: duplicate packet (ACK was lost). Do NOT write again, just ACK.
        // - If off == expected_off: this is the next expected packet, write it and advance expected_off.
        // - If off > expected_off: unexpected/out-of-order for stop-and-wait, request the expected offset.
        if (off < expected_off) {
            // Duplicate, just ACK it again
            snprintf(reply, sizeof(reply), "ACK %u", off);
            send_reply(s, &ack_addr, reply);
            printf("DUP ACK %u\n", off);
            continue;
        }

        if (off > expected_off) {
            // Out-of-order; ask for what we expect (simple recovery)
            snprintf(reply, sizeof(reply), "NACK %u", expected_off);
            send_reply(s, &ack_addr, reply);
            printf("OOO NACK expected %u (got %u)\n", expected_off, off);
            continue;
        }

        // off == expected_off: write and advance
        if (fseek(out, (long)off, SEEK_SET) != 0) {
            fprintf(stderr, "fseek() failed: %s\n", strerror(errno));
            break;
        }
        size_t w = fwrite(payload, 1, (size_t)payload_len, out);
        if (w != (size_t)payload_len) {
            fprintf(stderr, "fwrite() failed: %s\n", strerror(errno));
            break;
        }

        expected_off += (uint32_t)payload_len;

        // ACK
        snprintf(reply, sizeof(reply), "ACK %u", off);
        if (send_reply(s, &ack_addr, reply) < 0) {
            fprintf(stderr, "sendto(ACK) failed: %s\n", strerror(errno));
            break;
        }
        printf("ACK %u\n", off);
    }

    

    // Close output file to flush buffers before hashing
    if (out) {
        fflush(out);
        fclose(out);
        out = NULL;
    }

    // Verify SHA256 
    if (expected_hash_hex[0]) {
        uint8_t calc_hash[SHA256_DIGEST_LENGTH];
        char calc_hex[65];

        if (compute_sha256_file(filename, calc_hash) == 0) {
            sha256_to_hex(calc_hash, calc_hex);

            if (strcmp(calc_hex, expected_hash_hex) == 0) {
                printf("File OK (SHA256 match)\n");
            } else {
                printf("File CORRUPTED (SHA256 mismatch)\n");
            }
        } else {
            printf("Could not compute SHA256\n");
        }
    } else {
        printf("No expected HASH received; skipping file hash verification.\n");
    }

    close(s);
    return 0;
}


static void parse_info_payload(
    const char *payload,
    size_t payload_len,
    char *out_filename,
    size_t out_filename_cap,
    uint32_t *out_expected_size,
    char out_expected_hash_hex[65]
) {
    size_t i = 0;

    while (i < payload_len) {
        // find end of line
        size_t line_start = i;
        while (i < payload_len && payload[i] != '\n') {
            i++;
        }
        size_t line_len = i - line_start;

        // process one line
        if (line_len >= 5 && !memcmp(payload + line_start, "NAME=", 5)) {
            size_t len = line_len - 5;
            if (len >= out_filename_cap) len = out_filename_cap - 1;
            memcpy(out_filename, payload + line_start + 5, len);
            out_filename[len] = '\0';
        }
        else if (line_len >= 5 && !memcmp(payload + line_start, "SIZE=", 5)) {
            char tmp[32];
            size_t len = line_len - 5;
            if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
            memcpy(tmp, payload + line_start + 5, len);
            tmp[len] = '\0';
            *out_expected_size = (uint32_t)strtoul(tmp, NULL, 10);
        }
        else if (line_len >= 5 && !memcmp(payload + line_start, "HASH=", 5)) {
            size_t len = line_len - 5;
            if (len > 64) len = 64;
            memcpy(out_expected_hash_hex, payload + line_start + 5, len);
            out_expected_hash_hex[len] = '\0';
        }

        // skip '\n'
        if (i < payload_len && payload[i] == '\n') {
            i++;
        }
    }
}


static int receive_info_and_reply(
    int s,
    const uint8_t *buf,
    size_t nbytes,
    const struct sockaddr_in *ack_addr,
    char *out_filename,
    size_t out_filename_cap,
    uint32_t *out_expected_size,
    char out_expected_hash_hex[65]
) {
    if (nbytes < INFO_HDR) return 0;
    if (memcmp(buf, "INFO", 4) != 0) return 0;

    // Extract id and crc
    uint32_t net_id = 0, net_crc = 0;
    memcpy(&net_id,  buf + 4, 4);
    memcpy(&net_crc, buf + 8, 4);

    uint32_t id = ntohl(net_id);
    uint32_t recv_crc = ntohl(net_crc);

    size_t payload_len = nbytes - INFO_HDR;
    const uint8_t *payload = buf + INFO_HDR;

    // Validate CRC over payload only
    uint32_t calc_crc = crc32(payload, payload_len);

    char reply[64];

    if (calc_crc != recv_crc) {
        snprintf(reply, sizeof(reply), "NACK %u", id);
        if (sendto(s, reply, strlen(reply), 0,
                   (const struct sockaddr *)ack_addr, (socklen_t)sizeof(*ack_addr)) < 0) {
            fprintf(stderr, "sendto(NACK INFO) failed: %s\n", strerror(errno));
            return -1;
        }
        return 1;
    }

    // CRC OK -> parse payload and ACK
    parse_info_payload((const char *)payload, payload_len,
                       out_filename, out_filename_cap,
                       out_expected_size, out_expected_hash_hex);

    snprintf(reply, sizeof(reply), "ACK %u", id);
    if (sendto(s, reply, strlen(reply), 0,
               (const struct sockaddr *)ack_addr, (socklen_t)sizeof(*ack_addr)) < 0) {
        fprintf(stderr, "sendto(ACK INFO) failed: %s\n", strerror(errno));
        return -1;
    }

    return 1;
}