#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <set>

typedef unsigned char BYTE;

int cstore_delete(UserArgs parsed_args)
{
    if(parsed_args.password.empty())
    {
        char * pass = getpass("Please enter a password: ");
        parsed_args.password = pass;
        free(pass);
    }

    if(parsed_args.files.empty())
    {
        std::cerr << "Files are empty. Please specify at least one file to delete from " << parsed_args.archivename << std::endl;
        return 1;
    }

    std::set<std::string> files(parsed_args.files.begin(), parsed_args.files.end());
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

    // MAIN LOOP
    std::ofstream new_archive_file(archivename, std::ios::out | std::ios::binary | std::ios::trunc);
    if(!new_archive_file.is_open())
    {
        std::cerr << "Could not open new archive file to write undeleted contents to.\n";
        return 1;
    }

    std::vector<BYTE> content;
    bool deleted_file = false;
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

                if(files.count(name) != 0)
                {
                    deleted_file = true;
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
            if (content_ctr < contentsize - 1)
            {
                content.push_back(ch);
                content_ctr++;
            }
            else
            {
                content.push_back(ch);

                // Write to new file if undeleted (still encrypted, so no need to reencrypt)
                if(!deleted_file)
                {
                    // Get filename as cstring
                    std::string name(name_bytes.begin(),name_bytes.end());
                    char * cstr = new char [name.length()+1];
                    std::strcpy (cstr, name.c_str());

                    // Put vector into a char*
                    char content_bytes[content.size()];
                    for(int i = 0; i < content.size(); i++)
                    {
                        content_bytes[i] = content[i];
                    }

                    // Write to new file (append operation)
                    new_archive_file.write(reinterpret_cast<const char*>(&namesize), sizeof namesize);
                    new_archive_file.write(cstr, strlen(cstr));
                    new_archive_file.write(reinterpret_cast<const char*>(&contentsize), sizeof contentsize);
                    new_archive_file.write(content_bytes, contentsize);
                }
                else
                {
                    std::string name(name_bytes.begin(), name_bytes.end());
                    std::cout << name << " deleted from " << archivename << ".\n";
                }

                name_bytes.clear();
                content.clear();
                content_ctr = 0;
                deleted_file = false;
                content_mode = false;
                namesize_mode = true;
            }
        }
    }

    new_archive_file.close();

    // new_archive_file now contains all the file contents, but no MAC
    
    // I/O: Encrypted archive file (we just updated)
    std::vector<BYTE> encrypted_file_content;
    BYTE encrypted_file_mac[SHA256_BLOCK_SIZE];

    // New archives don't have MAC code yet
    read_mac_archive(archivename, encrypted_file_mac, encrypted_file_content, 0);

    // Put the contents into a BYTE array
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

    return 0;
}