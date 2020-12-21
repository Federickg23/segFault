#include <string>
#include <iostream>
#include <stdio.h>
#include <algorithm>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "mail_utils.h"

int main()
{
    // Set flags for parsing input
    bool mailFromMode = true;
    bool rcptToMode = false;
    bool dataMode = false;
    bool skipMode = false;
    int bytesRead = 0;

    // Store all full messages parsed
    std::vector<FullMessage> fullMessages;

    // Read the input file (preventing overflow)
    std::string line;
    
    // Store read data while reading
    std::string mailFromUsername;
    std::vector<std::string> rcptToUsernames;
    std::vector<std::string> messageLines;
    
    try
    {
        while (std::getline(std::cin, line))
        {
            if (line.empty())
            {
                bytesRead += 1;
                if (bytesRead > MAX_MSG_SIZE)
                {
                    std::cerr << "Maximum message size exceeded. Aborting mail-in parsing.\n";
                    return 1;
                }
            }
            else
            {
                bytesRead += line.size();
                if (bytesRead > MAX_MSG_SIZE)
                {
                    std::cerr << "Maximum message size exceeded. Aborting mail-in parsing.\n";
                    return 1;
                }
            }

            // SKIP MODE -- get to end of line '.'
            if (skipMode)
            {
                if (line.empty())
                {
                    continue;
                }
                if (line == ".")
                {
                    // Flush out the variables, ready for new message
                    mailFromUsername.clear();
                    rcptToUsernames.clear();
                    messageLines.clear();

                    skipMode = false;
                    mailFromMode = true;
                    rcptToMode = false;
                    dataMode = false;
                }
            }
            // MODE 1: MAIL FROM:<username>
            else if(mailFromMode && !rcptToMode && !dataMode && !skipMode)
            {
                // Reject newlines out of place
                if (line.empty())
                {
                    std::cerr << "Empty line found in control lines. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue; 
                }

                // Check correct MAIL FROM format
                if (!checkMailFrom(line))
                {
                    std::cerr << "MAIL FROM control line invalid formatting. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Extract username from brackets
                std::string testUsername = extractUsername(line); 
                if ( !validMailboxChars(testUsername) )
                {
                    std::cerr << "Invalid MAIL FROM username. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                if( !doesMailboxExist(testUsername) )
                {
                    std::cerr << "Invalid MAIL FROM username. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }
                else
                {
                    mailFromUsername = testUsername;
                }

                // Change modes
                mailFromMode = false;
                rcptToMode = true;
                dataMode = false;
            }
            // MODE 2: RCPT TO:<username>
            else if(rcptToMode && !mailFromMode && !dataMode && !skipMode)
            {
                // Reject newlines out of place
                if (line.empty())
                {
                    std::cerr << "Empty line found in control lines. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Check if this line is the DATA delimiter (if so, continue)
                if(checkDataDelimiter(line))
                {
                    // Invalid if there are no valid rcptTo usernames (valid if at least one)
                    if ( rcptToUsernames.empty() )
                    {
                        std::cerr << "No valid RCPT TO lines. Skipping to end-of-message.\n";
                        skipMode = true;
                        continue;
                    }

                    // Switch mode
                    mailFromMode = false;
                    rcptToMode = false;
                    dataMode = true;
                    continue;
                }

                // Check correct RCPT TO format
                if (!checkRcptTo(line))
                {
                    std::cerr << "RCPT TO control line invalid formatting. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Extract username from brackets
                std::string testUsername = extractUsername(line);
                if( !validMailboxChars(testUsername) )
                {
                    std::cerr << "Invalid RCPT TO username. Violates formatting." << std::endl;
                }
                else
                {
                    rcptToUsernames.push_back(testUsername);
                }
            }
            // MODE 3: DATA
            else if(dataMode && !mailFromMode && !rcptToMode && !skipMode)
            {
                // Empty lines just get added as newlines
                if (line.empty())
                {
                    messageLines.push_back("\n");
                    continue;
                }

                // End of message check
                if (line == ".")
                {
                    FullMessage newMessage;
                    newMessage.mailFrom = mailFromUsername;
                    std::sort( rcptToUsernames.begin(), rcptToUsernames.end() );
                    rcptToUsernames.erase( std::unique( rcptToUsernames.begin(), rcptToUsernames.end() ), rcptToUsernames.end() );
                    newMessage.rcptTo = rcptToUsernames;
                    newMessage.data = messageLines;
                    fullMessages.push_back(newMessage);

                    // Flush out the variables, ready for new message
                    mailFromUsername.clear();
                    rcptToUsernames.clear();
                    messageLines.clear();

                    // Switch back to mailFrom mode
                    mailFromMode = true;
                    rcptToMode = false;
                    dataMode = false;
                }
                // Actual content
                else
                {
                    if (line[0] == '.')
                    {
                        line = line.substr(1);
                    }
                    
                    messageLines.push_back(line);
                }
            }
        }
    }
    catch (const std::bad_alloc& e)
    {
        std::cerr << "Memory allocation failed. Aborting mail-in file parsing. Nice try. \n"; 
        return 1;
    }

    //std::cout << "Messages found: " << fullMessages.size() << std::endl;
    for ( FullMessage const&  fullMessage : fullMessages)
    {
        std::vector<std::string> writeList = ipcHelper(fullMessage);
        for ( std::string sendTo : fullMessage.rcptTo)
        {
            // Open up mail-out for each message we want to mailbox to send to
            int pipe_fd[2];
            pid_t p;

            if (pipe(pipe_fd) == -1) 
            {
                std::cerr << "Pipe failed." << std::endl;
                return 1;
            }

            p = fork();    
            if (p < 0) 
            {
                // Failed fork
                std::cerr << "Fork failed." << std::endl;
                return 1;
            }
            else if (p == 0)
            {
                // Child process
                close(pipe_fd[1]);               // Close the writing end of the pipe
                close(STDIN_FILENO);             // Close the current stdin 
                dup2(pipe_fd[0], STDIN_FILENO);  // Replace stdin with the reading end of the pipe
                execl("./bin/mail-out", "./bin/mail-out", sendTo.data(), NULL);
            } 
            else 
            {
                // Parent process
                int status;
                close(pipe_fd[0]); // Close the reading end of the pipe
                for ( std::string writeStr : writeList )
                {
                    write(pipe_fd[1], writeStr.c_str(), strlen(writeStr.c_str()) + 1);
                }
                close(pipe_fd[1]);
                p = wait(&status);
                if (WEXITSTATUS(status) == 1)
                {
                    std::cerr << "mail-out invocation failed on message from " << fullMessage.mailFrom << std::endl;
                }
            }
        }
    }

    return 0;
}