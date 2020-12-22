#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>

typedef unsigned char BYTE;

int cstore_extract(UserArgs parsed_args)
{
    if(parsed_args.password.empty())
    {
        char * pass = getpass("Please enter a password: ");
        parsed_args.password = pass;
        free(pass);
    }

    if(parsed_args.files.empty())
    {
        std::cerr << "Files are empty. Please specify at least one file to extract from " << parsed_args.archivename << std::endl;
        return 1;
    }

    std::vector<std::string> files = parsed_args.files;
    std::string password = parsed_args.password;
    std::string archivename = parsed_args.archivename;

    // Hash password to get key
    BYTE HMAC_key[SHA256_BLOCK_SIZE];
    iterate_sha256(password, HMAC_key, HMAC_SHA256_ITERS);
    BYTE encryption_key[SHA256_BLOCK_SIZE];
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
    for (std::string file : files)
    {
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
    }
    return 0;
}