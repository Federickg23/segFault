#include <sys/stat.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <vector>
#include <algorithm>
#include <regex>
#include "mail_utils.h"
namespace fs = std::filesystem;

#define MAILBOX_NAME_MAX 255
#define MAIL_FROM_MAX 12
#define RCPT_TO_MAX 10

/*
Input: (std::string) A string.
Output: (boolean) Whether the string's characters are all alphabetic.
Gives back whether a string only has alphabetic characters.
*/
bool isAlpha(const std::string &str)
{
    bool alpha = true;

    // Make sure string has a single char
    if (str.empty())
    {
        alpha = false;
    }

    // Check incrementally that all characters are alphabetical
    for(char const &c : str)
    {
        if( !alpha || !std::isalpha(c) )
        {
            alpha = false;
            break;
        }        
    }

    return alpha;
}

/*
Input: (std::string) A string.
Output: (boolean) Whether a string's characters are all valid mailbox chars.
Checks whether characters are included in upper and lower case letters, digits, +, -, and _
*/
bool validMailboxChars(const std::string &str)
{    
    if (str.empty())
    {
        return false;
    }

    // First character must be alphabetic
    if (!std::isalpha(str[0]))
    {
        return false;
    }

    for(char const &c : str)
    {
        if (!std::isalpha(c) && 
        !std::isdigit(c) && 
        c != '+' && c != '-' && c != '_')
        {
            return false;
        }
    }

    return true;
}

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid MAIL FROM format.
Returns an indication of whether line is in correct MAIL FROM format.
*/
bool checkMailFrom(const std::string &line)
{
    // Regex for MAIL FROM:<username>
    std::regex mail_from_regex("^[mM][aA][iI][lL] [fF][rR][oO][mM]:<.{1,255}>$");

    // Check characters do not exceed maximum possible length
    if (line.length() > MAILBOX_NAME_MAX + MAIL_FROM_MAX)
    {
        return false;
    }

    // Check MAIL FROM:<username> format
    if ( !std::regex_match(line, mail_from_regex) )
    {
        return false;
    }

    return true;
}

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid DATA (delimiter) format.
Returns an indication of whether line is in correct DATA format.
*/
bool checkDataDelimiter(const std::string &line)
{
    // Regex for MAIL FROM:<username>
    std::regex rgx("^[dD][aA][tT][aA]$");

    // Check characters do not exceed maximum possible length
    if (line.length() > MAILBOX_NAME_MAX + RCPT_TO_MAX)
    {
        return false;
    }

    // Check DATA format
    if ( !std::regex_match(line, rgx) )
    {
        return false;
    }

    return true;
}

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid RCPT TO format.
Returns an indication of whether line is in correct RCPT TO format.
*/
bool checkRcptTo(const std::string &line)
{
    // Regex for MAIL FROM:<username>
    std::regex rgx("^[rR][cC][pP][tT] [tT][oO]:<.{1,255}>$");

    // Check characters do not exceed maximum possible length
    if (line.length() > MAILBOX_NAME_MAX + MAIL_FROM_MAX)
    {
        return false;
    }

    // Check RCP TO:<username> format
    if ( !std::regex_match(line, rgx) )
    {
        return false;
    }

    return true;
}

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether this line is the end of message indicator.
Returns boolean of whether line is the end of message indicator.
*/
bool checkEndOfMessage(const std::string &line)
{
    // Regex for MAIL FROM:<username>
    if(line == ".")
    {
        return true;
    }
    else
    {
        return false;
    }
}

/*
Input: (std::string) Control line from mail message.
Output: (std::string) Parsed username from middle of brackets.
Returns the username in the brackets.
std::string extractUsername(const std::string &line)
{
    // Regex for brackets
    std::regex rgx("<(.*?)>");
    std::smatch match;
    std::string username;

    std::regex_search(line, match, rgx);
    std::ssub_match sub_match = match[1];
    username = sub_match.str();

    return username;
}
*/

/*
Input: (std::string) Control line from mail message.
Output: (std::string) Parsed username from middle of brackets.
Returns the username in the brackets.
*/
std::string extractUsername(const std::string &line)
{
    bool readUsername = false;
    std::string username;

    for(char const &c : line)
    {
        if ( readUsername )
        {
            username += c;
        }
        else if ( c == '<')
        {
            readUsername = true;
        }
    }

    username = username.substr(0, username.size() - 1);
    return username;
}

/* 
Input: (std::string) Mailbox name.
Output: (bool) Whether mailbox directory exists in system or not.
Checks if mailbox path exists (used by mail-out)
*/
bool doesMailboxExist(const std::string &s)
{
    // Must check valid mailbox characters first
    if ( !validMailboxChars(s) )
    {
        return false;
    }

    std::string mail_prefix = "./mail/";
    std::string mailbox_path = mail_prefix + s;
    struct stat buffer;
    return (stat (mailbox_path.c_str(), &buffer) == 0);
}

/*
Input: (std::string) Mailbox name, (std::string) File name.
Output: (std::string) Path to new writing new file.
Gives back the appropriate path to write the new mailed file to.
*/
std::string newMailPath(const std::string &mailbox_name, const std::string &file_name)
{
    const std::string mail_prefix = "./mail/";
    std::string mailbox_path = mail_prefix + mailbox_name + "/" + file_name;
    return mailbox_path;
}

/*
Input: (std::string) A string.
Output: (boolean) Whether the string's characters are all numeric.
Gives back whether a string only has numeric characters.
*/
bool isNumeric(const std::string &str)
{
    return std::all_of(str.begin(), str.end(), ::isdigit);
}

/* 
Input:  (std::string) Mailbox name.
Output: (std::string) Next message name in current mailbox.
Checks the current highest numbering of the messages in the mailbox
and returns the next number.
*/
std::string get_stem(const fs::path &p) { return (p.stem().string()); }
std::string getNextNumber(const std::string &mailbox_name)
{
    std::string mail_prefix = "./mail/";
    std::string mailbox_path = mail_prefix + mailbox_name;
    std::vector<std::string> files;

    // Iterate over the directory
    for(const auto & entry : fs::directory_iterator(mailbox_path))
    {
        try
        {
            files.push_back(get_stem(entry.path()));
        }
        catch(...)
        {
            return "ERROR";
        }
    }

    // Get the maximum number file
    int max = 0;
    for(std::string file_name : files)
    {
        // Check that file is appropriate length
        if (file_name.length() > 5)
        {
            return "ERROR";
        }

        // Check that file ONLY has numbers
        if (!isNumeric(file_name))
        {
            return "ERROR";
        }
        
        file_name.erase(0, file_name.find_first_not_of('0'));
        int num;

        // Check that file can be converted to a number
        try
        {
            num = std::stoi(file_name);
        }
        catch(std::invalid_argument &e)
        {
            return "ERROR";
        }
        
        if (num > max)
        {
            max = num;
        }
    }

    // Format new file number in ##### format
    int new_num = max + 1;
    std::string num_str = std::to_string(new_num);
    while(num_str.length() < 5)
    {
        num_str = "0" + num_str;
    }

    return num_str;
}

std::vector<std::string> ipcHelper(FullMessage fullMessage)
{
    std::vector<std::string> writeList;

    // FROM line
    std::string headerFrom;
    headerFrom = "From: " + fullMessage.mailFrom + "\n";
    writeList.push_back(headerFrom);

    // TO line
    std::string headerTo = "To: ";
    for (std::string rcpt : fullMessage.rcptTo)
    {
        headerTo = headerTo + rcpt + ", ";
    }
    headerTo.pop_back();
    headerTo.pop_back();
    headerTo = headerTo + "\n";
    writeList.push_back(headerTo);

    // Line break character
    writeList.push_back("\n");

    // Message lines
    for(std::string msgLine : fullMessage.data)
    {
        if ( msgLine == "\n")
        {
            writeList.push_back("\n");
        } 
        else
        {
            std::string formattedMsg = msgLine + "\n";
            writeList.push_back(formattedMsg);
        }
    }

    return writeList;
}