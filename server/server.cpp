#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <sys/wait.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "list.h"
#include "encrypt.h"
#include "extract.h"
#include "remove.h"
#include "cstore_utils.h"
#include "mail_utils.h"

namespace my {

template<class T> struct DeleterOf;
template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };
template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
{
    BIO_push(upper.get(), lower.release());
    return upper;
}

class StringBIO {
    std::string str_;
    my::UniquePtr<BIO_METHOD> methods_;
    my::UniquePtr<BIO> bio_;
public:
    StringBIO(StringBIO&&) = delete;
    StringBIO& operator=(StringBIO&&) = delete;

    explicit StringBIO() {
        methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
        if (methods_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_meth_new");
        }
        BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
            std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
            str->append(data, len);
            return len;
        });
        bio_.reset(BIO_new(methods_.get()));
        if (bio_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_new");
        }
        BIO_set_data(bio_.get(), &str_);
        BIO_set_init(bio_.get(), 1);
    }
    BIO *bio() { return bio_.get(); }
    std::string str() && { return std::move(str_); }
};

[[noreturn]] void print_errors_and_exit(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}

[[noreturn]] void print_errors_and_throw(const char *message)
{
    my::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
}

std::string receive_some_data(BIO *bio)
{
    char buffer[1024];
    int len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0) {
        my::print_errors_and_throw("error in BIO_read");
    } else if (len > 0) {
        return std::string(buffer, len);
    } else if (BIO_should_retry(bio)) {
        return receive_some_data(bio);
    } else {
        my::print_errors_and_throw("empty BIO_read");
    }
}

std::vector<std::string> split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

std::string receive_http_message(BIO *bio)
{
    std::string headers = my::receive_some_data(bio);
    char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += my::receive_some_data(bio);
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers+4, &headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : my::split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            auto header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                content_length = std::stoul(colon+1);
            }
        }
    }
    while (body.size() < content_length) {
        body += my::receive_some_data(bio);
    }
    return headers + "\r\n" + body;
}

void send_http_response(BIO *bio, const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    BIO_write(bio, body.data(), body.size());
    BIO_flush(bio);
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
{
    if (BIO_do_accept(accept_bio) <= 0) {
        return nullptr;
    }
    return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

} // namespace my


void receiveMessage(std::string request){

}


int parseRequest(std::string request){
    if(strcmp(request.substr(0,3).c_str(), "GET") != 0){
        return -1;
    }
    std::vector<FullMessage> fullMessages;


    std::string delimiter = "\n";
    size_t pos = 0;
    std::string token;
    int counter = 0;
    bool mailFromMode = true;
    bool rcptToMode = false;
    bool dataMode = false;
    bool skipMode = false;
    std::string mailFromUsername;
    std::vector<std::string> rcptToUsernames;
    std::vector<std::string> messageLines;
    int bytesRead = 0;

    while ((pos = request.find(delimiter)) != std::string::npos) {
        token = request.substr(0, pos);
        std::cout << token << std::endl;
        if(counter == 2 && token.find("send") != std::string::npos ){
            std::cout << "Client is sending a message" << std::endl;
        }
        else if (counter == 2 && token.find("receive") != std::string::npos){
            std::cout << "Client is receiving a message" << std::endl;
            receiveMessage(request);
            break;
        }
        else if (counter == 2){
            return -1;
        }
        if (token.empty())
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
                bytesRead += token.size();
                if (bytesRead > MAX_MSG_SIZE)
                {
                    std::cerr << "Maximum message size exceeded. Aborting mail-in parsing.\n";
                    return 1;
                }
            }
            // SKIP MODE -- get to end of line '.'
            if (skipMode)
            {
                if (token.empty())
                {
                    continue;
                }
                if (token == ".")
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
                if (token.empty())
                {
                    std::cerr << "Empty line found in control lines. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue; 
                }

                // Check correct MAIL FROM format
                if (!checkMailFrom(token))
                {
                    std::cerr << "MAIL FROM control line invalid formatting. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Extract username from brackets
                std::string testUsername = extractUsername(token); 
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
                if (token.empty())
                {
                    std::cerr << "Empty line found in control lines. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Check if this line is the DATA delimiter (if so, continue)
                if(checkDataDelimiter(token))
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
                if (!checkRcptTo(token))
                {
                    std::cerr << "RCPT TO control line invalid formatting. Skipping to end-of-message.\n";
                    skipMode = true;
                    continue;
                }

                // Extract username from brackets
                std::string testUsername = extractUsername(token);
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
                if (token.empty())
                {
                    messageLines.push_back("\n");
                    continue;
                }

                // End of message check
                if (token == ".")
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
                    if (token[0] == '.')
                    {
                        token = token.substr(1);
                    }
                    
                    messageLines.push_back(token);
                }
            }

        request.erase(0, pos + delimiter.length());

    }
    return 0;
}

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

    if (SSL_CTX_use_certificate_file(ctx.get(), "serv_cert.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "private/priv_key.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server private key");
    }
    if (!SSL_CTX_load_verify_locations(ctx.get(),"../certs/ca/certs/ca.cert.pem",NULL)) {
                	ERR_print_errors_fp(stderr);
                	exit(1);
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, NULL); //Set to require client certificate verification 
    SSL_CTX_set_verify_depth(ctx.get(),1);  

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("8080"));
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 8080)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    while (auto bio = my::accept_new_tcp_connection(accept_bio.get())) {
        bio = std::move(bio)
            | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
            ;
        try {
            std::string request = my::receive_http_message(bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());
            parseRequest(request.c_str()); 

            my::send_http_response(bio.get(), "okay cool\n");
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}
