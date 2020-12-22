#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <set> 
#include "cstore_list.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

typedef unsigned char BYTE;

int cstore_list(std::string archivename)
{
    std::vector<BYTE> file_content;
    BYTE file_mac[SHA256_BLOCK_SIZE];
    int length = read_mac_archive(archivename, file_mac, file_content, SHA256_BLOCK_SIZE);

    if(length == 1)
    {
        return 1; // Couldn't read mac archive
    }
    
    std::set<std::string> filenames;
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
    char namesize_bytes[4];
    char contentsize_bytes[4];
    std::vector<BYTE> name_bytes;
    for(BYTE ch : file_content)
    {
        if (namesize_mode)
        {
            if (namesize_ctr < 3)
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
                filenames.insert(name);
                // std::cout << " - " << name << std::endl;
                name_bytes.clear();
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
            // Skip over the contents of the file
            if (content_ctr < contentsize - 1)
            {
                content_ctr++;
            }
            else
            {
                content_ctr = 0;
                content_mode = false;
                namesize_mode = true;
            }
        }
    }

    std::cout << archivename << " (" << length << " bytes):\n";
    for(std::string filename : filenames)
    {
        std::cout << " - " << filename << std::endl;
    }

    return 0;
}