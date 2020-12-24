#include <stdio.h>
#include <cstring>
#include <memory.h>
#include <string.h>
#include <vector>
#include <iostream>
#include <fstream>
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"

int read_mac_archive(const std::string archivename, BYTE* file_mac, std::vector<BYTE>& file_content, int mac_len)
{
    // I/O: Open old archivename
    std::ifstream old_archive_file(archivename, std::ios::in | std::ios::binary);
    if(!old_archive_file.is_open())
    {
        std::cout << "Archive does not exist." << std::endl; 
        return 1;
    }

    // Authenticate with HMAC if existing archive. Not needed if new archive with no files.
    // Get length of file:
    old_archive_file.seekg (0, old_archive_file.end);
    int length = old_archive_file.tellg();
    old_archive_file.seekg (0, old_archive_file.beg);

    char filebuf[length];

    // Read data as a block:
    old_archive_file.read(filebuf, length);

    if (!old_archive_file)
    {
        std::cerr << "error: only " << old_archive_file.gcount() << " could be read";
        return 1;
    }

    // Copy over the file as two parts: (1) MAC (2) Content
    for(int i = 0; i < length; i++)
    {
        if (i < mac_len)
        {
            file_mac[i] = filebuf[i];
        }
        else
        {
            file_content.push_back(filebuf[i]);
        }
    }

    old_archive_file.close();

    return length;
}

int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len)
{
    // Pad key with 32 bytes to make it 64 bytes long
    BYTE key_prime[HMAC_BLOCKSIZE];
    int padding_len = HMAC_BLOCKSIZE - key_len; // will always be 32 bytes
    memcpy(key_prime, key, key_len);
    for(int i = 0; i < padding_len; i++)
    {
        key_prime[padding_len + i] = 0x00;
    }

    // Inner padding
    BYTE i_key_pad[HMAC_BLOCKSIZE];
    for(int i = 0; i < HMAC_BLOCKSIZE; i++)
    {
        i_key_pad[i] = key_prime[i] ^ 0x5c;
    }

    // Outer Padding
    BYTE o_key_pad[HMAC_BLOCKSIZE];
    for(int i = 0; i < HMAC_BLOCKSIZE; i++)
    {
        o_key_pad[i] = key_prime[i] ^ 0x36;
    }

    // Concatenate ipad and opad section: (o_key_pad || H(i_key_pad || m))
    // First, concatenate i_key_pad and message, then hash
    int i_key_pad_message_len = message_len + HMAC_BLOCKSIZE;
    BYTE i_key_pad_message[i_key_pad_message_len];
    memcpy(&i_key_pad_message[0], i_key_pad, HMAC_BLOCKSIZE);
    memcpy(&i_key_pad_message[HMAC_BLOCKSIZE], message, message_len);

    BYTE hashed_i_key_pad[SHA256_BLOCK_SIZE];
    hash_sha256(i_key_pad_message, hashed_i_key_pad, i_key_pad_message_len);

    // Second, concatenate the o_key_pad and H(i_key_pad || m)
    int o_key_pad_concat_len = SHA256_BLOCK_SIZE + HMAC_BLOCKSIZE;
    BYTE o_key_pad_concat[o_key_pad_concat_len];
    memcpy(&o_key_pad_concat[0], o_key_pad, HMAC_BLOCKSIZE);
    memcpy(&o_key_pad_concat[HMAC_BLOCKSIZE], hashed_i_key_pad, SHA256_BLOCK_SIZE);

    // Finally, hash the entire thing
    hash_sha256(o_key_pad_concat, out_tag, o_key_pad_concat_len);
    return 0;
}

int encrypt_cbc(std::vector<BYTE> plaintext, const BYTE * IV, BYTE ciphertext[], BYTE* key, int keysize, int final_len)
{
    // Pad the plaintext first
    std::vector<BYTE> padded_plaintext = pad_cbc(plaintext);
    BYTE plaintext_bytes[padded_plaintext.size()];
    for (int i = 0; i < padded_plaintext.size(); i++)
    {
        plaintext_bytes[i] = padded_plaintext[i];
    }

    // Key setup
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256); // 256 is digest of SHA-256 (our key)

    // Encryption starts here:
	BYTE plaintext_block[AES_BLOCK_SIZE], xor_block[AES_BLOCK_SIZE], encrypted_block[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    
    // Check if padding worked
    if(padded_plaintext.size() % AES_BLOCK_SIZE != 0 
        || padded_plaintext.size() != plaintext.size() + (AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE)))
    {
        std::cerr << "Padding failed. Plaintext is not a multiple of AES Blocksize.\n";
        return 1;
    }

    //std::cout << "Padded Plaintext: ";
    //print_hex(plaintext_bytes, padded_plaintext.size());
    //std::cout << std::endl;
    int num_blocks = final_len / AES_BLOCK_SIZE;

    // Main Loop
    // Transfer over IV to buffer
    for(int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        iv_buf[i] = IV[i];
    } 

    // Append the IV to the beginning of final ciphertext 
    memcpy(&ciphertext[0], IV, AES_BLOCK_SIZE);

    for(int i = 1; i < num_blocks; i++) // Start at 1 because IV is first block
    {
		memcpy(plaintext_block, &plaintext_bytes[(i - 1) * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

        // XOR plaintext and IV
        for(int j = 0; j < AES_BLOCK_SIZE; j++)
        {
            xor_block[j] = plaintext_block[j] ^ iv_buf[j];
        }
		
		aes_encrypt(xor_block, encrypted_block, key_schedule, keysize); // Output saved in encrypted_block
		memcpy(&ciphertext[i * AES_BLOCK_SIZE], encrypted_block, AES_BLOCK_SIZE); // Output ciphertext block
		memcpy(iv_buf, encrypted_block, AES_BLOCK_SIZE);
    }

    // Check if the length is as expected
    if(final_len != num_blocks * AES_BLOCK_SIZE)
    {
        std::cerr << "Encryption length is not the expeted final length. Please check padding again\n";
        return 1;
    }

    return 0;
}

int decrypt_cbc(const BYTE* ciphertext, std::vector<BYTE> &decrypted_plaintext, BYTE* key, int keysize, int input_len)
{
    // Key setup
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256); // 256 is digest of SHA-256 (our key)

    //std::cout << "Ciphertext: ";
    //print_hex(ciphertext, input_len);
    //std::cout << std::endl;

    // Extract IV from ciphertext
    BYTE iv_buf[AES_BLOCK_SIZE];
    memcpy(iv_buf, &ciphertext[0], AES_BLOCK_SIZE);

    // Decrypt the ciphertext
    BYTE ciphertext_block[AES_BLOCK_SIZE], xor_block[AES_BLOCK_SIZE], decrypted_block[AES_BLOCK_SIZE];
    BYTE plaintext[input_len - AES_BLOCK_SIZE]; // Ciphertext size minus an IV

    if (input_len % AES_BLOCK_SIZE != 0)
    {
        std::cerr << "Ciphertext is not a multiple of the AES blocksize. This is not a CBC ciphertext\n";
        return 1;
    }

	int num_blocks = (input_len - AES_BLOCK_SIZE) / AES_BLOCK_SIZE;

    // MAIN LOOP
    for (int i = 0; i < num_blocks; i++) 
    {
		memcpy(ciphertext_block, &ciphertext[(i + 1) * AES_BLOCK_SIZE], AES_BLOCK_SIZE); // +1 because IV is the first block
        aes_decrypt(ciphertext_block, decrypted_block, key_schedule, keysize);
		
        // XOR decrypted block and IV
        for(int j = 0; j < AES_BLOCK_SIZE; j++)
        {
            xor_block[j] = decrypted_block[j] ^ iv_buf[j];
        }
        
		memcpy(&plaintext[i * AES_BLOCK_SIZE], xor_block, AES_BLOCK_SIZE);
		memcpy(iv_buf, ciphertext_block, AES_BLOCK_SIZE);
	}

    // std::cout << "Decrypted Ciphertext: ";
    // print_hex(plaintext, input_len - AES_BLOCK_SIZE);
    // std::cout << std::endl;

    // Remove padding from the plaintext
    std::vector<BYTE> unpad_plaintext = unpad_cbc(plaintext, input_len - AES_BLOCK_SIZE);
    //std::cout << "Unpadded Plaintext: ";
    //print_hex(unpad_plaintext);
    //std::cout << std::endl;

    // Write unpadded plaintext
    for(int i = 0; i < unpad_plaintext.size(); i++)
    {
        // decrypted_out[i] = unpad_plaintext[i];
        decrypted_plaintext.push_back(unpad_plaintext[i]);
    }

    return 0;
}

int sample_urandom(BYTE sampled_bits[], int sample_len)
{
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
    if(urandom.is_open())
    {
        for(int i = 0; i < sample_len; i++)
        {
            BYTE random_value; //Declare value to store data into
            size_t size = sizeof(random_value); //Declare size of data

            if(urandom) //Check if stream is open
            {
                urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
                if(urandom) //Check if stream is ok, read succeeded
                {
                    sampled_bits[i] = random_value;
                }
                else //Read failed
                {
                    std::cerr << "Failed to read from /dev/urandom" << std::endl;
                    return 1;
                }
            }
        }
    }
    else
    {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return 1;
    }

    urandom.close(); //close stream
    return 0;
}

std::vector<BYTE> pad_cbc(std::vector<BYTE> data)
{
    int padlen = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    char padding = 0x01;
    for(int i = 0; i < padlen; i ++)
    {
        data.push_back(padlen);
    }
    
    /*
    for(char ch : data)
    {
        printf("%.2X", ch);
    }
    */

    return data;
}

std::vector<BYTE> unpad_cbc(const BYTE* padded_data, int len)
{
    // Check padding amount
    int pad_code = (int) padded_data[len - 1];

    // Write to new BYTE vector the unpadded data
    std::vector<BYTE> unpadded_data;
    for(int i = 0; i < len - pad_code; i++)
    {
        unpadded_data.push_back(padded_data[i]);
    }

    return unpadded_data;
}

void sample_random(char * buf, int sample_bytes)
{

}

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

void print_hex(const std::vector<BYTE> byte_arr)
{
    for(int i = 0; i < byte_arr.size(); i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

void hash_sha256(const BYTE * input, BYTE * output, int in_len)
{
    SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, input, in_len);
	sha256_final(&ctx, output);
}

void iterate_sha256(std::string password, BYTE* final_hash, int rounds)
{
    // Convert password into BYTE array of chars
    BYTE password_bytes[password.length()+1];
    for(int i = 0; i < password.length(); i++)
    {
        password_bytes[i] = password[i];
    }
    password_bytes[password.length()] = '\0';

    // Iteratively hash 10k times

    // First time needs to hash variable length password_bytes
    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, password_bytes, password.length() + 1);
    sha256_final(&ctx, buf);
    
    // Other 10,000 times hashes buffer (32 bytes)
    BYTE new_buf[SHA256_BLOCK_SIZE];
    for(int i = 0; i < rounds; i++)
    {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, buf, password.length() + 1);
        sha256_final(&ctx, new_buf);
        memcpy(buf, new_buf, sizeof(buf));
    }

    // Update the final hash
    for(int i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        final_hash[i] = buf[i];
    }
}

void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
              << "<function> can be: list, add, extract, delete.\n"
              << "Options:\n"
              << "\t-h, --help\t\t Show this help message.\n"
              << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
              << std::endl; 
}

UserArgs::UserArgs()
{
    this -> parse_success = false;
}

UserArgs::UserArgs(std::string password, std::vector<std::string> nonpass_args)
{
    this->password = password;
    this->nonpass_args = nonpass_args;
    this->parse_success = true;
    
    if (nonpass_args.size() == 1)
    {
        this -> archivename = nonpass_args[0];
    }
    else
    {
        this -> archivename = nonpass_args[0];
        // couldn't find a better way to slice lmao
        for(int i = 1; i < nonpass_args.size(); i++)
        {
            this -> files.push_back(nonpass_args[i]);
        }
    }
};

UserArgs parse_args(int argc, char* argv[], std::string function)
{
    std::vector<std::string> nonpass_args;
    std::string password; 

    for(int i = 2; i < argc; i++)
    {
        std::string arg = argv[i];
        if ((arg == "-h") || (arg == "--help")) 
        {
            show_usage(argv[0]);
            return UserArgs();
        } 
        else if (arg == "-p") 
        {
            if (i + 1 < argc) 
            {   // Make sure we aren't at the end of argv!
                password = argv[i + 1]; // Increment 'i' so we don't get the argument as the next argv[i].
                i++;
                if (i + 1 == argc) // Reached the end of argv.
                {
                    break;
                }
            } 
            else 
            { // No argument to the pass option.
                std::cerr << "-p option requires one argument." << std::endl;
                return UserArgs();
            }  
        }
        else
        {
            nonpass_args.push_back(argv[i]);
        }
    }

    if(nonpass_args.empty())
    {
        std::cerr << "cstore " << function << " requires an archivename.\n";  
        return UserArgs();
    }

    return UserArgs(password, nonpass_args);
}