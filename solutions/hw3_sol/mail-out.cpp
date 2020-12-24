#include <string>
#include <iostream>
#include <vector>
#include <fstream>
#include "mail_utils.h"

int main(int argc, char* argv[])
{
    // Check that mail directory is given
    if (argc != 2)
    {
        return 1; // mail-out cannot print to std::err, only return code
    }

    // Check the mail directory is valid
    std::string mailbox_name = argv[1];
    if (!validMailboxChars(mailbox_name) || mailbox_name.length() > MAILBOX_NAME_MAX || !doesMailboxExist(mailbox_name))
    {
        return 1; // mail-out cannot print to std::err, only return code
    }

    // Read the input file (preventing overflow)
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(std::cin, line))
    {
        if (line.empty())
        {
            std::string newline_only = "\n";
            lines.push_back("\n");
        }
        else
        {
            lines.push_back(line + "\n"); // getline removes newline
        }

        std::cin.clear();
        std::cin.ignore(); // Clear leftover getline byte
    }

    // Get next message number in mailbox
    std::string next_file_name = getNextNumber(mailbox_name);

    // Check if getNextNumber failed (should not have to worry about this)
    if (next_file_name == "ERROR")
    {
        return 1; // mail-out cannot print to std::err, only return code
    }

    std::string new_mail_path = newMailPath(mailbox_name, next_file_name); // Get path to write to

    // Write to the correct mailbox
    std::ofstream new_file;
    new_file.open(new_mail_path, std::ios::trunc);
    if(new_file.is_open())
    {
        for (std::string line : lines)
        {
            new_file << line;
        }
        new_file.close();
    }
    else
    {
        return 1; // mail-out cannot print to std::err, only return code
    }
    
    return 0;
}
