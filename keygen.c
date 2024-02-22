#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

void sha256(const char *input, unsigned char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
}

void sha512(const char *input, unsigned char *output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, input, strlen(input));
    SHA512_Final(hash, &sha512);
    int i = 0;
    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
}

size_t b64_encoded_size(size_t inlen)
{
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0){
        ret += 3 - (inlen % 3);
    }
    ret /= 3;
    ret *= 4;

    return ret;
}

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *in, size_t len)
{
    char   *out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out  = malloc(elen+1);
    out[elen] = '\0';

    for (i=0, j=0; i<len; i+=3, j+=4) {
        v = in[i];
        v = i+1 < len ? v << 8 | in[i+1] : v << 8;
        v = i+2 < len ? v << 8 | in[i+2] : v << 8;

        out[j]   = b64chars[(v >> 18) & 0x3F];
        out[j+1] = b64chars[(v >> 12) & 0x3F];
        if (i+1 < len) {
            out[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j+2] = '=';
        }
        if (i+2 < len) {
            out[j+3] = b64chars[v & 0x3F];
        } else {
            out[j+3] = '=';
        }
    }

    return out;
}

int main() {

    // Specify the file path
    const char *file_path = "/sys/firmware/devicetree/base/serial-number";

    // Open the file in read mode
    FILE *file = fopen(file_path, "r");

    // Check if the file opened successfully
    if (file == NULL) {
        perror("Error opening file");
        return 1; // Exit the program with an error code
    }

    char buffer[1024]; // Buffer to store read data
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        fwrite(buffer, 1, bytesRead, stdout); // Print to the console
    }

    // Close the file
    fclose(file);

    // Calculate SHA-512 hash
    unsigned char sha512_output[SHA512_DIGEST_LENGTH];
    sha512(buffer, sha512_output);

    // Calculate SHA-256 hash
    unsigned char sha256_output[SHA256_DIGEST_LENGTH];
    sha256(sha512_output, sha256_output);

    // Calculate SHA-512 hash
    unsigned char sha512_output_final[SHA512_DIGEST_LENGTH];
    sha512(sha256_output, sha512_output_final);

    char *base64_encoded = base64_encode(sha512_output_final, SHA512_DIGEST_LENGTH);
    //printf("Final result: %s\n", base64_encoded);
    printf("%s\n", base64_encoded);
    return 0;
}

