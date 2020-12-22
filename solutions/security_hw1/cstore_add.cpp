#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>  
#include <unistd.h>
#include <string>
#include <cstring>

int cstore_add(UserArgs parsed_args)
{
    if(parsed_args.password.empty())
    {
        char * pass = getpass("Please enter a password: ");
        parsed_args.password = pass;
        free(pass);
    }

    if(parsed_args.files.empty())
    {
        std::cerr << "Files are empty. Please specify at least one file to add to " << parsed_args.archivename << std::endl;
        return 1;
    }

    std::vector<std::string> files = parsed_args.files;
    std::string password = parsed_args.password;
    std::string archivename = parsed_args.archivename;

    for (std::string file : files)
    {
        std::ifstream input_file(file, std::ios::in | std::ios::binary);
        if (!input_file.is_open())
        {
            std::cerr << "Error reading " << file << ". Please check if it exists.\n";
            return 1; 
        }

        // Get length of file
        input_file.seekg(0, std::ios::end);
        int length = input_file.tellg();
        input_file.seekg (0, std::ios::beg);

        // Reject if file is empty
        if(length == 0)
        {
            std::cerr << "Archive does not accept empty files. Please check that your file contains at least one byte of content.\n";
            return 1;
        }

        input_file.close();
    }

    // Hash password to get key
    BYTE HMAC_key[SHA256_BLOCK_SIZE];
    iterate_sha256(password, HMAC_key, HMAC_SHA256_ITERS);
    BYTE encryption_key[SHA256_BLOCK_SIZE];
    iterate_sha256(password, encryption_key, ENCRYPT_SHA256_ITERS);

    // I/O: Open old archivename
    bool new_archive = false;
    std::ifstream old_archive_file(archivename, std::ios::in | std::ios::binary);
    if(!old_archive_file.is_open())
    {
        std::cout << "Archive does not exist. Creating archive " << archivename << "..." << std::endl; 
        new_archive = true;
    }

    // Authenticate with HMAC if existing archive. Not needed if new archive with no files.
    if(!new_archive)
    {
        // Get length of file:
        old_archive_file.seekg (0, old_archive_file.end);
        int length = old_archive_file.tellg();
        old_archive_file.seekg (0, old_archive_file.beg);

        if(length < 32)
        {
            std::cerr << "Archive is formatted incorrectly. Cannot add to archives not following specification.\n";
            return 1;
        }

        char filebuf[length];

        // Read data as a block:
        old_archive_file.read(filebuf, length);

        if (!old_archive_file)
        {
            std::cerr << "error: only " << old_archive_file.gcount() << " could be read";
            return 1;
        }

        // Copy over the file as two parts: (1) MAC (2) Content
        BYTE file_mac[SHA256_BLOCK_SIZE];
        BYTE file_content[length - SHA256_BLOCK_SIZE];
        for(int i = 0; i < length; i++)
        {
            if (i < SHA256_BLOCK_SIZE)
            {
                file_mac[i] = filebuf[i];
            }
            else
            {
                file_content[i - SHA256_BLOCK_SIZE] = filebuf[i];
            }
        }

        // Authenticate with HMAC
        BYTE hmac_tag[SHA256_BLOCK_SIZE];
        hmac(file_content, HMAC_key, hmac_tag, length - SHA256_BLOCK_SIZE, SHA256_BLOCK_SIZE);

        // The check:
        if(memcmp(hmac_tag, file_mac, SHA256_BLOCK_SIZE))
        {
            std::cerr << "Authentication failed.\n";
            return 1;
        }
    }

    old_archive_file.close();

    // I/O: Write to new archivename
    std::ofstream new_archive_file(archivename, std::ios::out | std::ios::binary | std::ios::app);
    if(!new_archive_file.is_open())
    {
        std::cerr << "Could not write to archive file " << archivename << std::endl; 
    }

    for (std::string file : files)
    {
        std::ifstream input_file(file, std::ios::in | std::ios::binary);
        if (!input_file.is_open())
        {
            std::cerr << "Error reading " << file << ". Please check if it exists.\n";
            return 1; 
        }

        // Get filename and length of filename
        char cstr[file.length()+1];
        std::strcpy (cstr, file.c_str());

        // Get length of file
        input_file.seekg(0, std::ios::end);
        int length = input_file.tellg();
        input_file.seekg (0, std::ios::beg);

        // Reject if file is empty
        if(length == 0)
        {
            std::cerr << "Archive does not accept empty files. Please check that your file contains at least one byte of content.\n";
            return 1;
        }

        // Write in order of: (1) Filename Size (2) Filename (3) Content Size (4) Contents
        // Write: (1) Filename Size (2) Filename
        int filename_size = file.length();
        new_archive_file.write(reinterpret_cast<const char*>(&filename_size), sizeof filename_size);
        new_archive_file.write(cstr, strlen(cstr));

        // ENCRYPT THE DATA
        input_file.seekg (0, std::ios::beg);
        std::ostringstream ss;
        ss << input_file.rdbuf();
        const std::string& s = ss.str();
        std::vector<BYTE> filebuf(s.begin(), s.end());
        BYTE IV[16];
        int iv_len = 16;
        sample_urandom(IV, iv_len);
        int final_len = length + (AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE)) + AES_BLOCK_SIZE; // Extra block for IV
        BYTE ciphertext[final_len]; // Appropriate padded ciphertext length

        // Double check that the decryption also works
        std::vector<BYTE> double_check;

        int encrypt_success = encrypt_cbc(filebuf, IV, ciphertext, encryption_key, 256, final_len);
        int decrypt_success = decrypt_cbc(ciphertext, double_check, encryption_key, 256, final_len);

        // Check if encryption succeeded (and decrypts correctly)
        BYTE double_check_bytes[double_check.size()];
        for(int i = 0; i < double_check.size(); i++)
        {
            double_check_bytes[i] = double_check[i];
        }
        BYTE filebuf_bytes[filebuf.size()];
        for(int i = 0; i < filebuf.size(); i++)
        {
            filebuf_bytes[i] = filebuf[i];
        }
        if(encrypt_success != 0 && !memcmp(double_check_bytes, filebuf_bytes, filebuf.size()))
        {
            std::cerr << "Encryption failed for " << file << std::endl;
            return 1;
        }

        // Write: (3) Content Size (ciphertext size) (4) Contents (encrypted)
        new_archive_file.write(reinterpret_cast<const char*>(&final_len), sizeof final_len);
        new_archive_file.write(reinterpret_cast<const char*>(ciphertext), final_len);

        input_file.close();
    } 

    new_archive_file.close();

    // I/O: Encrypted archive file (we just updated)
    std::vector<BYTE> encrypted_file_content;
    BYTE encrypted_file_mac[SHA256_BLOCK_SIZE];

    // New archives don't have MAC code yet
    if(new_archive)
    {
        read_mac_archive(archivename, encrypted_file_mac, encrypted_file_content, 0);
    }
    else
    {
        read_mac_archive(archivename, encrypted_file_mac, encrypted_file_content, SHA256_BLOCK_SIZE);
    }
    
    BYTE encrypted_file_content_bytes[encrypted_file_content.size()];
    for(int i = 0; i < encrypted_file_content.size(); i++)
    {
        encrypted_file_content_bytes[i] = encrypted_file_content[i];
    }
        
    // I/O: Final archive file
    std::ofstream final_archive_file(archivename, std::ios::out | std::ios::binary | std::ios::trunc);
    if(!final_archive_file.is_open())
    {
        std::cerr << "Could not complete final write to archive file " << archivename << std::endl; 
    }

    // HMAC on the entire encrypted archive
    BYTE hmac_tag[SHA256_BLOCK_SIZE];
    hmac(encrypted_file_content_bytes, HMAC_key, hmac_tag, encrypted_file_content.size(), SHA256_BLOCK_SIZE);
    char hmac_tag_char[SHA256_BLOCK_SIZE];
    memcpy(hmac_tag_char, hmac_tag, SHA256_BLOCK_SIZE);

    // Place tag at beginning of file and write the rest
    final_archive_file.write(hmac_tag_char, SHA256_BLOCK_SIZE);
    char encrypted_file_content_char[encrypted_file_content.size()];
    memcpy(encrypted_file_content_char, encrypted_file_content_bytes, encrypted_file_content.size());
    final_archive_file.write(encrypted_file_content_char, encrypted_file_content.size());
    final_archive_file.close();

    std::cout << "Add operation success.\n";

    return 0;
}