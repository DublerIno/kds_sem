// sender.c for macos/linux     
// Usage: sender <target ip> <targetport> <localport> <file>


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h> 

#include <unistd.h>         // close()
#include <sys/socket.h>     // socket(), sendto(), recvfrom(), setsockopt()
#include <netinet/in.h>     // sockaddr_in - ipv4 address structures
#include <arpa/inet.h>      // inet_pton() - convert ip string to binary
#include <sys/time.h>       // timeval structure for socket timeout setting

#include <openssl/sha.h> // SHA256
#include "util.h" //crc32 functions
 
// Configuration
#define PACKET_MAX 1024             // Max UDP packet size

// DATA packet header: 4B "DATA" + 4B offset + 4B crc32
#define DATA_HDR   12
#define PAYLOAD_MAX (PACKET_MAX - DATA_HDR)


// Control message StopandWait
static int send_control_sw( int s, const struct sockaddr_in *target_addr, uint32_t ctrl_id, const char *msg);

//return the size of the file in bytes
static uint32_t get_fsize(FILE* f){
    fseek(f, 0, SEEK_END);
    long s = ftell(f);
    fseek(f, 0, SEEK_SET);
    return (uint32_t)s;
}

//return the pointer to the last filename separator
static const char* basename_simple(const char* p){
    const char* a = strrchr(p,'\\');
    const char* b = strrchr(p,'/');
    const char* c = (a && b) ? (a>b?a:b) : (a?a:b);
    return c ? c+1 : p;
}


//Send to wrapper for text
static int send_text(int s, const struct sockaddr_in *dst, const char *msg) {
    ssize_t n = sendto(s, msg, strlen(msg), 0, (const struct sockaddr*)dst, (socklen_t)sizeof(*dst));
    return (n < 0) ? -1 : 0;
}

int main(int argc, char** argv) {
    // Usage: sender <ip> <target port> <local port> <file>
    if (argc != 5) {
        fprintf(stderr, "Wrong number of arguments. Usage: %s <ip> <target port> <local port> <file>\n", argv[0]);
        return 1;
    }

    // Initialize CRC table
    crc32_init();

    const char* ip   = argv[1];
    int port = atoi(argv[2]);
    int ackport = atoi(argv[3]);
    const char* path = argv[4];

    // Open file in read binary mode 
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open file %s\n", path);
        return 1;
    }

    uint32_t fsize = get_fsize(f);

    // Create UDP socket, endpoint
    int s = socket(AF_INET, SOCK_DGRAM, 0); 

    //domain = AF_INET defines adress as ipv4, 
    //type = SOCK_DGRAM defines datagram socket = connectionless, only seperate packets
    if (s < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        fclose(f);
        return 1;
    }
    
    // Bind socket to ACK port to receive ACK/NACKs
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(ackport);       // ACK port
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    // Destination address (receiver IP:port)
    struct sockaddr_in target_addr; //IPv4 socket address
    memset(&target_addr, 0, sizeof(target_addr)); //zero out target_addr
    target_addr.sin_family = AF_INET;
    target_addr.sin_port   = htons((unsigned short)port);
    // Convert IP string to binary form
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton() failed for IP '%s'\n", ip);
        close(s);
        fclose(f);
        return 1;
    }

    // Set receive timeout so recvfrom() doesn't block forever, for stop-and-wait ARQ
    struct timeval tv;
    tv.tv_sec  = 1;  // 1 second
    tv.tv_usec = 0;
    //setsockopt for options, RCVTIMEO accepts timeval structure
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv)) < 0) {
        fprintf(stderr, "setsockopt(SO_RCVTIMEO) failed: %s\n", strerror(errno));
        close(s);
        fclose(f);
        return 1;
    }

    //--COMUNICATION SEQUENCE: INFO packet ( NAME, SIZE, HASH ), START, DATA packets, STOP --
    char line[512];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    char hash_hex[65];


    //COMPUTE FILE HASH 
    if (compute_sha256_file(path, hash) < 0) {
        fprintf(stderr, "Failed to compute SHA256\n");
        return 1;
    }
    sha256_to_hex(hash, hash_hex);


    // Send INFO packet = 
    // DATA Packet:
    //   [0..3]   "info"
    //   [8..11]  crc32(payload) (uint32_t, network order)
    //   [12..]   name, size, hash strings separated by \n

    if (send_info_sw(s, &target_addr, path, fsize, hash_hex) < 0) {
        fprintf(stderr, "Failed to send INFO packet\n");
        close(s);
        fclose(f);
        return 1;
    }
    printf("Sent INFO packet (name, size, hash)\n");
        

    // START
    send_control_sw(s, &target_addr, ACK_START, "START");

    // DATA Packet:
    //   [0..3]   "DATA"
    //   [4..7]   offset (uint32_t, network order)
    //   [8..11]  crc32(payload) (uint32_t, network order)
    //   [12..]   payload bytes
    uint8_t pkt[PACKET_MAX];
    memcpy(pkt, "DATA", 4);

    //pkt == &pkt[0] 
    //pkt + DATA_HDR == &pkt[12] - start of payload

    uint32_t off = 0;
    // Stop-and-wait loop: send one DATA packet, wait for ACK/NACK, retransmit if needed
    while (off < fsize) {
        size_t payload_len = PAYLOAD_MAX;

        //reduce payload length
        if (fsize < off + payload_len) {
            payload_len = fsize - off;
        }

        // Correct endianness - data interpretation in network order
        uint32_t netoff = htonl(off);
        memcpy(pkt + 4, &netoff, 4);

        // Read payload from file
        size_t got = fread(pkt + DATA_HDR, 1, payload_len, f);
        if (got != payload_len) {
            fprintf(stderr, "fread() failed at off=%u (got %zu, payload_len %zu)\n", off, got, payload_len);
            goto out;
        }

        // Compute CRC over payload and store it 
        uint32_t crc = crc32(pkt + DATA_HDR, payload_len);
        uint32_t netcrc = htonl(crc);
        memcpy(pkt + 8, &netcrc, 4);

        for (;;) {
            // Send DATA packet
            ssize_t sent = sendto(s,pkt, (ssize_t)(payload_len + DATA_HDR), 0,
                (const struct sockaddr*)&target_addr,
                (socklen_t)sizeof(target_addr)
            );
            if (sent < 0) {
                fprintf(stderr, "sendto(DATA) failed: %s\n", strerror(errno));
                goto out;
            }

            printf("Sent packet offset %u (%zu bytes payload)\n", off, payload_len);

            // Wait for reply - ACK/NACK
            char reply[128];
            struct sockaddr_in peer;
            socklen_t peerlen = (socklen_t)sizeof(peer);

            int n = (int)recvfrom(s, reply, (int)sizeof(reply) - 1, 0, (struct sockaddr*)&peer, &peerlen);
            if (n < 0) {
                // Timeout -> retransmit
                fprintf(stderr, "recvfrom() timeout, resending offset %u\n", off);
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
                goto out;
            }

            reply[n] = '\0';

            uint32_t ack_off = 0;

            // ACK: wait for ACK and correct offset
            if (sscanf(reply, "ACK %u", &ack_off) == 1 && ack_off == off) {
                off += (uint32_t)payload_len;
                break;
            }

            // NACK: resend same offset
            if (sscanf(reply, "NACK %u", &ack_off) == 1 && ack_off == off) {
                continue;
            }
        }
    }

    // STOP 
    send_control_sw(s, &target_addr, ACK_START, "STOP");

out:
    close(s);
    fclose(f);
    return 0;
}



static int send_control_sw(
    int s,
    const struct sockaddr_in *target_addr,
    uint32_t ctrl_id,
    const char *msg
) {
    for (;;) {
        if (sendto(s, msg, (int)strlen(msg), 0,
                   (const struct sockaddr*)target_addr, (socklen_t)sizeof(*target_addr)) < 0) {
            fprintf(stderr, "sendto(%s) failed: %s\n", msg, strerror(errno));
            return -1;
        }

        char reply[128];
        struct sockaddr_in peer;
        socklen_t peerlen = (socklen_t)sizeof(peer);

        int n = (int)recvfrom(s, reply, (int)sizeof(reply) - 1, 0,
                              (struct sockaddr*)&peer, &peerlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // timeout -> retransmit same control message
                continue;
            }
            fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
            return -1;
        }

        reply[n] = '\0';

        uint32_t ack_id = 0;
        if (sscanf(reply, "ACK %u", &ack_id) == 1 && ack_id == ctrl_id) {
            return 0; // success
        }
        if (sscanf(reply, "NACK %u", &ack_id) == 1 && ack_id == ctrl_id) {
            continue; // resend
        }

        // ignore unrelated ACKs (e.g., delayed DATA ACK)
    }
}

static int send_info_sw(
    int s,
    const struct sockaddr_in *target_addr,
    const char *file_path,
    uint32_t fsize,
    const char *hash_hex   // 64 hex chars for SHA-256, NUL-terminated
) {
    char line[512];

    uint8_t info_pkt[PACKET_MAX];
    uint8_t *p = info_pkt;

    // "INFO"
    memcpy(p, "INFO", 4);
    p += 4;

    // ID (network order)
    uint32_t net_id = htonl(INFO_ID);
    memcpy(p, &net_id, 4);
    p += 4;

    // Reserve CRC space (fill later)
    uint8_t *crc_ptr = p;
    p += 4;

    // Build payload: NAME, SIZE, HASH (newline-separated)
    snprintf(line, sizeof(line), "NAME=%s", basename_simple(file_path));
    size_t name_len = strlen(line);
    if ((size_t)(p - info_pkt) + name_len + 1 > PACKET_MAX) {
        fprintf(stderr, "INFO payload too large (NAME)\n");
        return -1;
    }
    memcpy(p, line, name_len);
    p += name_len;
    *p++ = '\n';

    snprintf(line, sizeof(line), "SIZE=%u", (unsigned)fsize);
    size_t size_len = strlen(line);
    if ((size_t)(p - info_pkt) + size_len + 1 > PACKET_MAX) {
        fprintf(stderr, "INFO payload too large (SIZE)\n");
        return -1;
    }
    memcpy(p, line, size_len);
    p += size_len;
    *p++ = '\n';

    snprintf(line, sizeof(line), "HASH=%s", hash_hex);
    size_t hash_len = strlen(line);
    if ((size_t)(p - info_pkt) + hash_len + 1 > PACKET_MAX) {
        fprintf(stderr, "INFO payload too large (HASH)\n");
        return -1;
    }
    memcpy(p, line, hash_len);
    p += hash_len;
    *p++ = '\n';

    // Compute payload length (bytes after INFO_HDR)
    size_t payload_len = (size_t)(p - info_pkt - INFO_HDR);

    // CRC over payload only
    uint32_t crc = crc32(info_pkt + INFO_HDR, payload_len);
    uint32_t net_crc = htonl(crc);
    memcpy(crc_ptr, &net_crc, 4);

    // Total packet length
    size_t pkt_len = INFO_HDR + payload_len;

    // Stop-and-Wait retransmission loop
    for (;;) {
        ssize_t sent = sendto(
            s,
            info_pkt,
            pkt_len,
            0,
            (const struct sockaddr *)target_addr,
            (socklen_t)sizeof(*target_addr)
        );
        if (sent < 0) {
            fprintf(stderr, "sendto(INFO) failed: %s\n", strerror(errno));
            return -1;
        }

        char reply[128];
        struct sockaddr_in peer;
        socklen_t peerlen = (socklen_t)sizeof(peer);

        int n = (int)recvfrom(
            s,
            reply,
            (int)sizeof(reply) - 1,
            0,
            (struct sockaddr *)&peer,
            &peerlen
        );
        if (n < 0) {
            // Timeout -> retransmit INFO
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            fprintf(stderr, "recvfrom(INFO) failed: %s\n", strerror(errno));
            return -1;
        }

        reply[n] = '\0';

        uint32_t ack_id = 0;
        if (sscanf(reply, "ACK %u", &ack_id) == 1 && ack_id == INFO_ID) {
            return 0; // success
        }

        if (sscanf(reply, "NACK %u", &ack_id) == 1 && ack_id == INFO_ID) {
            continue; // resend
        }

        // Ignore unrelated replies (e.g., delayed ACK for data)
    }
}