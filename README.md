# kds_sem

UDP file transfer application implementing Stop-and-Wait ARQ with
packet-level CRC32 and file-level SHA-256 integrity verification.
Supports network impairment simulation using NetDerper.

---

## Build

### Sender (macOS / Linux)

Requires OpenSSL (`libcrypto`).

```bash
clang -Wall -Wextra -Wpedantic -std=c11 sender_unix.c util.c -o sender \
  -I/opt/homebrew/include -L/opt/homebrew/lib -lcrypto

./sender <target_ip> <target_port> <local_ack_port> <file>

./sender 127.0.0.1 14000 15001 img_small.png


udp.port == 14000 || udp.port == 14001 || udp.port == 15000 || udp.port == 15001
