#include <sys/stat.h>
#include <string>
#include <vector>
#ifndef MAIL_UTILS
#define MAIL_UTILS

/**** CONSTANTS ****/
#define MAILBOX_NAME_MAX 255
#define MAIL_FROM_MAX 12
#define RCPT_TO_MAX 10
#define MAX_MSG_SIZE 1e9

/**** STRUCTS ****/
struct FullMessage
{
    std::string mailFrom;
    std::vector<std::string> rcptTo;
    std::vector<std::string> data;
};

/**** FUNCTIONS ****/

/*
Input: (std::string) A string.
Output: (boolean) Whether the string's characters are all alphabetic.
Gives back whether a string only has alphabetic characters.
*/
bool isAlpha(const std::string &str);

/*
Input: (std::string) A string.
Output: (boolean) Whether a string's characters are all valid mailbox chars.
Checks whether characters are included in upper and lower case letters, digits, +, -, and _
*/
bool validMailboxChars(const std::string &str);

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid MAIL FROM format.
Returns an indication of whether line is in correct MAIL FROM format.
*/
bool checkMailFrom(const std::string &line);

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid RCPT TO format.
Returns an indication of whether line is in correct RCPT TO format.
*/
bool checkRcptTo(const std::string &line);

/*
Input: (std::string) Input line from mail-in parsed file.
Output: (bool) Whether the line is in valid DATA (delimiter) format.
Returns an indication of whether line is in correct DATA format.
*/
bool checkDataDelimiter(const std::string &line);

/*
Input: (std::string) Control line from mail message.
Output: (std::string) Parsed username from middle of brackets.
Returns the username in the brackets.
*/
std::string extractUsername(const std::string &line);

/* 
Input: (std::string) Mailbox name.
Output: (bool) Whether mailbox directory exists in system or not.
Checks if mailbox path exists (used by mail-out)
*/
bool doesMailboxExist(const std::string &s);

/*
Input: (std::string) A string.
Output: (boolean) Whether the string's characters are all numeric.
Gives back whether a string only has numeric characters.
*/
bool isNumeric(const std::string &str);

/*
Input: (std::string) Mailbox name, (std::string) File name.
Output: (std::string) Path to new writing new file.
Gives back the appropriate path to write the new mailed file to.
*/
std::string newMailPath(const std::string &mailbox_name, const std::string &file_name);

/* 
Input:  (std::string) Mailbox name.
Output: (std::string) Next message name in current mailbox.
Checks the current highest numbering of the messages in the mailbox
and returns the next number.
*/
std::string getNextNumber(const std::string &mailbox_name);

std::vector<std::string> ipcHelper(FullMessage fullMessage);

#endif
