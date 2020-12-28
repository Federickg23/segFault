#include <memory>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>

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
    char buffer[50000];
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

void send_http_request(BIO *bio, const std::string& line, std::string& message, const std::string& host, const std::string&  method)
{
    std::string request = line + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "Content-Length: " + std::to_string(message.size()) + "\r\n";
    request += method;
    request += "\r\n\r\n";
    request += message;

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);

}

SSL *get_ssl(BIO *bio)
{
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        my::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

std::string get_cert(char* filepath)
{
	// Check if username exists
	std::fstream file;
   	
	file.open(filepath, std::ios::in);  
   	if(!file.is_open()) //checking whether the file is open
   	{
		printf("Cert file not found\n");
		exit (1);
      	}
	
	std::string cert = "";
	std::string line;
      	while(getline(file, line))
	{
		cert += line + "\n";
	}

        file.close();
        return cert.substr(0, cert.size()-1);	
}

void verify_the_certificate(SSL *ssl, const std::string& expected_hostname)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
        exit(1);
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        fprintf(stderr, "No certificate was presented by the server\n");
        exit(1);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
        fprintf(stderr, "Certificate verification error: X509_check_host\n");
        exit(1);
    }
#else
    // X509_check_host is called automatically during verification,
    // because we set it up in main().
    (void)expected_hostname;
#endif
}

int get_cert_strings(std::string response, std::vector<std::string>& recipients, std::vector<std::string>& buffer)
{
	const char* break_line = strcasestr(&response[0], "\r\n\r\n");
	std::string body = break_line + 4;

	size_t pos = 0;
	// First find is of the recipients
	while ((pos = body.find(": ")) != std::string::npos) {
		
		std::string recipient = body.substr(0, pos);
    		body.erase(0, pos + 2); // Removes the recipient part
		
		// Now we find the end of the cert. We made it end with 2 new lines
		pos = body.find("\n\n");

		if (pos == std::string::npos)
		{
			// That means certificate was not found. So, we don't add this recipient nore certs.
			// As such, we delete this line too
			pos = body.find("\r\n");
			body.erase(0, pos + 2);
			continue;
		}

		std::string cert = body.substr(0, pos);
		// Add the certificate and the recipient, then delete it
		body.erase(0, pos + 2);

		buffer.push_back(cert);
		recipients.push_back(recipient);
		
	}

	// If at the end, the size of the buffer is 0, then no recipients found
	
	if(buffer.size() == 0)
		return 1;
	else 
		return 0;

}


} // namespace my

int main(int argc, char* argv[])
{

	if (argc < 5)
	{
		std::string message = "Usage: ./sendmsg [path/to/certificate] [path/to/message] -r [recipient1] [recipient2] ...";
		std::cerr << message << std::endl;
		exit(1);
	} 
	
	else if (argv[3] != std::string("-r"))
	{
		std::string message = "Usage: ./sendmsg [path/to/certificate] [path/to/message] -r [recipient1] [recipient2] ...";
		std::cerr << message << std::endl;
		exit(1);
	}

	// Before trying to connect, lets pull the message. Maybe theres an error when we pull it.
	
	std::fstream file;
	file.open(argv[2], std::ios::in);  
   	if(!file.is_open()) //checking whether the file is open
   	{
		std::cerr << "Message not found" << std::endl;
		exit(1);
	 
	}
	std::string line;
	std::string msg;
	while(getline(file, line))
		{msg += line + "\n";}
	file.close();
	msg = msg.substr(0,msg.size()-1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif
 
    if (SSL_CTX_use_certificate_file(ctx.get(), argv[1], SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading client certificate");
    }

    /* Load trusted CA. */ 
    if (!SSL_CTX_load_verify_locations(ctx.get(),"../certificates/root/ca/intermediate/certs/ca-chain.cert.pem",NULL)) {
                	ERR_print_errors_fp(stderr);
                	exit(1);
    }

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, NULL); //Set to require server certificate verification 
    SSL_CTX_set_verify_depth(ctx.get(),1);  
 
    auto bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
    if (bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    auto ssl_bio = std::move(bio)
        | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1))
        ;
    SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), "localhost");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), "localhost");
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), "localhost");
    
    // First request gets the user's certificates
    std::string message = "Certificate: ";
    message += my::get_cert(argv[1]);
    message += "\r\n";
    message += "Recipients: ";
    int i;
    for (i = 4; i < argc; i++)
    {
	    message += argv[i];
	    message += " "; // Last space is important! Server looks for it.
    } 
    message += "\r\n\r\n"; 
    my::send_http_request(ssl_bio.get(), "GET / HTTP/1.1", message, "localhost", "Method: sendmsg");
    std::string response = my::receive_http_message(ssl_bio.get());
    printf("%s", response.c_str());
   
    
    // Now, for each certificate, get the public key
    
    std::vector<std::string> recipients, cert_strings;

    if (my::get_cert_strings(response, recipients, cert_strings) == 1)
    {
	    std::cerr << "No certificates were found from the recipients" << std::endl;
	    exit(1);
    }

    // The second message sends an encyrpted message.
    // Must redo the handshake 
    bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
    if (bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    ssl_bio = std::move(bio)
        | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1))
        ;
    SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), "localhost");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), "localhost");
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), "localhost");

    message = "";
    for (int i = 0; i < (int)cert_strings.size(); i++)
    {
	    std::string rec = recipients.operator[](i);
	    std::string cert = cert_strings.operator[](i);
	    
	    BIO *cbio;
	    
	    cbio = BIO_new(BIO_s_mem());
	    BIO_puts(cbio, cert.c_str());
	   
	    X509 *certificate = PEM_read_bio_X509(cbio, NULL, 0, NULL);

	    STACK_OF(X509) *certs = sk_X509_new_null();
	    sk_X509_push(certs, certificate);

	    //certificate = NULL;

	    BIO *in = BIO_new_file(argv[2], "r");

	    /** 
	     * The issue here is, that the certificate was generated from a RANDOM private key, 
	     * but the public key was assigned to that random private key. Only the server knows it.
	     * As such, when the user recieves the message, they must use the private key used by the
	     * server. So basically, while this will send over encrypted messages, when messages are being
	     * read, they will have to be send over decrypted...since only the server can decrypt it.
	     */

	    CMS_ContentInfo *cms = CMS_encrypt(certs, in, EVP_des_ede3_cbc(), CMS_STREAM);

	    BIO *out = BIO_new(BIO_s_mem());
	    SMIME_write_CMS(out, cms, in, CMS_STREAM);
	    

   	    BUF_MEM *bio_buf;
	    BIO_get_mem_ptr(out, &bio_buf);
	    std::string encrypted = std::string(bio_buf->data, bio_buf->length);
	    
	    message += rec + ": ";
	    message += encrypted + "\r\n";
	}

    message += "\r\n";
    my::send_http_request(ssl_bio.get(), "POST / HTTP/1.1", message, "localhost", "Method: 2sendmsg");
    response = my::receive_http_message(ssl_bio.get());
    printf("%s", response.c_str());

}
