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

std::string get_message(std::string response)
{
	std::string delim = "Encrypted Message: ";

	size_t m1 = response.find(delim);

       	if (m1 == std::string::npos)
	{
		return "";
	}

	m1+= delim.size();
	std::string mes = response.substr(m1);

	return mes.substr(0, mes.find("\r\n\r\n"));
}

} // namespace my


void err()
{
	fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
	exit(1);
}

int main(int argc, char* argv[])
{

	if (argc != 3)
	{
		std::string usage = "Usage: ./recvmsg [path/to/certificate] [path/to/privatekey";
		std::cerr << usage << std::endl;
		exit(1);
	} 
	
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
    message += "\r\n\r\n";

    my::send_http_request(ssl_bio.get(), "GET / HTTP/1.1", message, "localhost", "Method: recvmsg");
    std::string response = my::receive_http_message(ssl_bio.get());
    //printf("%s", response.c_str());

    // Now we must decrypt the message
    std::string encmessage = my::get_message(response);

    if (encmessage == "")
    {
	    // No messages were in your inbox
	    // So do nothing
	    return 1; 
    }

    BIO *in, *out, *cbio, *kbio;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;

    cbio = BIO_new_file(argv[1], "r");

    rcert = PEM_read_bio_X509(cbio, NULL, 0, NULL);

    kbio = BIO_new_file(argv[2], "r");

    rkey = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL);

    if (!rcert || !rkey)
        err();

    /* Open S/MIME message to decrypt */

    in = BIO_new(BIO_s_mem());
    BIO_puts(in, encmessage.c_str());

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
        err();

    out = BIO_new(BIO_s_mem());
    if (!out)
        err();

    printf("HI\n");
    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        err();

    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(out, bio_buf);
    std::string dec = std::string(bio_buf->data, bio_buf->length);
    std::cout << dec << std::endl;

}
