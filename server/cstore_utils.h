#ifndef CSTORE_UTILS
#define CSTORE_UTILS
#include <vector>
#include <string>
#include "crypto_lib/aes.h"

#define HMAC_SHA256_ITERS 10000
#define ENCRYPT_SHA256_ITERS 20000 
#define HMAC_BLOCKSIZE 64

struct UserArgs
{
    std::string password;
    std::vector<std::string> nonpass_args;
    std::string archivename;
    std::vector<std::string> files;
    bool parse_success;

    UserArgs();
    UserArgs(std::string password, std::vector<std::string> nonpass_args);
};

void show_usage(std::string name);

int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len);

int read_mac_archive(const std::string archivename, BYTE* file_mac, std::vector<BYTE> &file_content, int mac_len);

int encrypt_cbc(std::vector<BYTE> plaintext, const BYTE* IV, BYTE ciphertext[], BYTE key[], int keysize, int final_len);

int decrypt_cbc(const BYTE* ciphertext, std::vector<BYTE> &decrypted_plaintext, BYTE* key, int keysize, int input_len);

int sample_urandom(BYTE sampled_bits[], int sample_len);

std::vector<BYTE> pad_cbc(std::vector<BYTE> data);

std::vector<BYTE> unpad_cbc(const BYTE* padded_data, int len);

void sample_random(char * buf, int sample_bytes);

void hash_sha256(const BYTE * input, BYTE * output, int in_len);

void iterate_sha256(std::string password, BYTE* final_hash, int rounds);

void print_hex(const BYTE* byte_arr, int len);

void print_hex(const std::vector<BYTE> byte_arr);

UserArgs parse_args(int argc, char* argv[], std::string function);

#endif