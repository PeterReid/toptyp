#include <stdint.h>

#define SHA1_DIGEST_SIZE 20

void sha1(uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]);
void sha1_hmac(uint8_t *key, size_t key_len, uint8_t *data, size_t data_len, uint8_t digest[SHA1_DIGEST_SIZE]);
