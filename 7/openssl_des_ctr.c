#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char *argv[])
{
    // Set the plaintext and secret key
    unsigned char plaintext[] = "Alice loves Bob";
    unsigned char key[] = "security";

    // Set the counter value
    unsigned char counter[] = {0x12, 0x34, 0x56, 0x78};

    // Initialize the cipher context
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context\n");
        return 1;
    }

    // Set the cipher type to DES in CTR mode
    if (EVP_EncryptInit_ex(ctx,EVP_des_ctr(), NULL, key, counter) != 1) {
        printf("Error initializing cipher context\n");
        return 1;
    }

    // Allocate memory for the ciphertext
    int plaintext_len = strlen(plaintext);
    int ciphertext_len = plaintext_len;
    unsigned char ciphertext[ciphertext_len];

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1) {
        printf("Error encrypting plaintext\n");
        return 1;
    }
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len) != 1) {
        printf("Error finalizing encryption\n");
        return 1;
    }
    ciphertext_len += final_len;

    // Print the ciphertext
    int i;
    for (i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
