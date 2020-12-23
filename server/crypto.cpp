#include "encrypt.h"
#include "cstore_utils.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <string>
#include <cstring>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"

int encrypt(char **argv, int argc)
{
    if (argc < 2) {
        std::cerr << "Missing args: requires receiver and file.";
        return 1;
    }
    std::string file(argv[1]);
    std::string receiver(argv[0]);

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


    // fetch hashed password from file
    BYTE HMAC_key[SHA256_BLOCK_SIZE];
    BYTE encryption_key[SHA256_BLOCK_SIZE];
    std::string pass;
    std::ifstream passwd_file;
    char mb_name[40];
    strcpy(mb_name, receiver.c_str());
    strcat(mb_name, ".txt");
    passwd_file.open(mb_name);
    if (!passwd_file)
    {
        std::cerr << "Error: could not open password file.";
        return 1;
    }
    getline(passwd_file, pass);
    passwd_file.close();
    const char *password = pass.c_str();
    iterate_sha256(password, encryption_key, ENCRYPT_SHA256_ITERS);

    // I/O: Open old mailbox
    bool make_box = false;
    std::ifstream mailbox(receiver, std::ios::in | std::ios::binary);
    if(!mailbox.is_open())
    {
        std::cout << "Mailbox empty. Creating mailbox..." << std::endl;
        make_box = true;
    }

    // Authenticate with HMAC if existing archive. Not needed if new archive with no files.
    if(!make_box)
    {
        // Get length of file:
        mailbox.seekg (0, mailbox.end);
        length = mailbox.tellg();
        mailbox.seekg (0, mailbox.beg);

        if(length < 32)
        {
            std::cerr << "Archive is formatted incorrectly. Cannot add to archives not following specification.\n";
            return 1;
        }

        char filebuf[length];

        // Read data as a block:
        mailbox.read(filebuf, length);

        if (!mailbox)
        {
            std::cerr << "error: only " << mailbox.gcount() << " could be read";
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

    mailbox.close();

    // I/O: Write to mailbox, create it if necessary
    std::ofstream new_mailbox(receiver, std::ios::out | std::ios::binary | std::ios::app);
    if(!new_mailbox.is_open())
    {
        std::cerr << "Could not open mailbox.\n";
        return 1;
    }


    // Get filename and length of filename
    char cstr[file.length()+1];
    std::strcpy (cstr, file.c_str());
    // Get length of file
    input_file.seekg(0, std::ios::end);
    length = input_file.tellg();
    input_file.seekg (0, std::ios::beg);

    // Reject if file is incorrect
    if(length == 0)
    {
        std::cerr << "Mailbox does not accept empty files.\n";
        return 1;
    }

    // Write in order of: (1) Filename Size (2) Filename (3) Content Size (4) Contents
    // Write: (1) Filename Size (2) Filename
    int filename_size = file.length();
    new_mailbox.write(reinterpret_cast<const char*>(&filename_size), sizeof filename_size);
    new_mailbox.write(cstr, strlen(cstr));

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
    new_mailbox.write(reinterpret_cast<const char*>(&final_len), sizeof final_len);
    new_mailbox.write(reinterpret_cast<const char*>(ciphertext), final_len);

    input_file.close();

    new_mailbox.close();

    // I/O: Encrypted archive file (we just updated)
    std::vector<BYTE> encrypted_file_content;
    BYTE encrypted_file_mac[SHA256_BLOCK_SIZE];

    // New archives don't have MAC code yet
    if(make_box)
    {
        read_mac_archive(receiver, encrypted_file_mac, encrypted_file_content, 0);
    }
    else
    {
        read_mac_archive(receiver, encrypted_file_mac, encrypted_file_content, SHA256_BLOCK_SIZE);
    }

    BYTE encrypted_file_content_bytes[encrypted_file_content.size()];
    for(int i = 0; i < encrypted_file_content.size(); i++)
    {
        encrypted_file_content_bytes[i] = encrypted_file_content[i];
    }

    // I/O: Final archive file
    std::ofstream final_archive_file(receiver, std::ios::out | std::ios::binary | std::ios::trunc);
    if(!final_archive_file.is_open())
    {
        std::cerr << "Could not complete final write to archive file " << receiver << std::endl;
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


typedef unsigned char BYTE;

int extract(char **argv, int argc)
{
    if(argc < 2)
    {
        printf("Missing required args.\n");
    }

    std::string file(argv[1]);
    std::string archivename(argv[0]) ;

    // Hash password to get key
    BYTE HMAC_key[SHA256_BLOCK_SIZE];
    BYTE encryption_key[SHA256_BLOCK_SIZE];
    std::string pass;
    std::ifstream passwd_file;
    char mb_name[40];
    strcpy(mb_name, archivename.c_str());
    strcat(mb_name, ".txt");
    passwd_file.open(mb_name);
    if (!passwd_file)
    {
        std::cerr << "Error: could not open password file.";
        return 1;
    }
    getline(passwd_file, pass);
    passwd_file.close();
    const char *password = pass.c_str();
    iterate_sha256(password, encryption_key, ENCRYPT_SHA256_ITERS);

    // Read file, store all in memory
    std::vector<BYTE> file_content;
    BYTE file_mac[SHA256_BLOCK_SIZE];
    read_mac_archive(archivename, file_mac, file_content, SHA256_BLOCK_SIZE);

    // Convert file_content to bytes
    BYTE file_content_bytes[file_content.size()];
    for(int i = 0; i < file_content.size(); i++)
    {
        file_content_bytes[i] = file_content[i];
    }

    // Authenticate with HMAC
    BYTE authenticate_tag[SHA256_BLOCK_SIZE];
    hmac(file_content_bytes, HMAC_key, authenticate_tag, file_content.size(), SHA256_BLOCK_SIZE);

    // The check:
    if(memcmp(authenticate_tag, file_mac, SHA256_BLOCK_SIZE))
    {
        std::cerr << "Authentication failed.\n";
        return 1;
    }

    // Loop over files requeseted to be extracted
    std::vector<BYTE> content;
    bool file_found = false;
    bool namesize_mode = true;
    bool name_mode = false;
    bool contentsize_mode = false;
    bool content_mode = false;
    int namesize = 0;
    int namesize_ctr = 0;
    int name_ctr = 0;
    int contentsize = 0;
    int contentsize_ctr = 0;
    int content_ctr = 0;
    char namesize_bytes[sizeof(int)];
    char contentsize_bytes[sizeof(int)];
    std::vector<BYTE> name_bytes;
    for(BYTE ch : file_content)
    {
        if (namesize_mode)
        {
            if (namesize_ctr < sizeof(int) - 1)
            {
                namesize_bytes[namesize_ctr] = ch;
                namesize_ctr++;
                continue;
            }

            // Find size of the filename
            namesize_bytes[namesize_ctr] = ch;
            std::memcpy(&namesize, namesize_bytes, sizeof namesize_bytes);
            namesize_ctr = 0;
            namesize_mode = false;
            name_mode = true;
        }
        else if (name_mode)
        {
            if (name_ctr < namesize - 1)
            {
                name_bytes.push_back(ch);
                name_ctr++;
            }
            else
            {
                name_bytes.push_back(ch);
                std::string name(name_bytes.begin(),name_bytes.end());

                // We found the current to-be-extracted file
                if(name == file)
                {
                    content.clear(); // Overwrite content if we found the file later
                    file_found = true;
                }

                name_ctr = 0;
                name_mode = false;
                contentsize_mode = true;
            }
        }
        else if (contentsize_mode)
        {
            if (contentsize_ctr < 3)
            {
                contentsize_bytes[contentsize_ctr] = ch;
                contentsize_ctr++;
                continue;
            }

            // Find size of the contents
            contentsize_bytes[contentsize_ctr] = ch;
            std::memcpy(&contentsize, contentsize_bytes, sizeof contentsize_bytes);
            contentsize_ctr = 0;
            contentsize_mode = false;
            content_mode = true;
        }
        else // content mode
        {
            std::string name(name_bytes.begin(),name_bytes.end());
            // Skip over the contents of the file
            if (content_ctr < contentsize - 1)
            {
                if(file_found && name == file)
                {
                    content.push_back(ch);
                }
                content_ctr++;
            }
            else
            {
                if(file_found && name == file)
                {
                    content.push_back(ch);
                }
                content_ctr = 0;
                name_bytes.clear();
                content_mode = false;
                namesize_mode = true;
            }
        }
    }

    if(file_found)
    {
        // Decrypt file and write to current directory
        std::string test_filename = file;
        std::ofstream extracted_file(test_filename, std::ios::out | std::ios::binary | std::ios::trunc);
        if(!extracted_file.is_open())
        {
            std::cerr << "Could not complete final write to extracted file " << file << std::endl;
        }

        // Convert BYTE content vector to BYTE*
        BYTE content_bytes[content.size()];
        for(int i = 0; i < content.size(); i++)
        {
            content_bytes[i] = content[i];
        }
        std::vector<BYTE> plaintext;
        int decrypt_success = decrypt_cbc(content_bytes, plaintext, encryption_key, 256, content.size());
        if(decrypt_success != 0)
        {
            std::cerr << "Decryption failed for " << file << std::endl;
            return 1;
        }

        char plaintext_bytes[plaintext.size()];
        for(int i = 0; i < plaintext.size(); i++)
        {
            plaintext_bytes[i] = plaintext[i];
        }

        extracted_file.write(plaintext_bytes, plaintext.size());
        std::cout << file << " (" << plaintext.size() << " bytes) successfully extracted.\n";
        extracted_file.close();
    }
    else
    {
        std::cout << file << " not found in archive.\n";
    }

    content.clear();
    contentsize = 0;
    file_found = false;

    return 0;
}

