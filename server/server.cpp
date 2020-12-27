#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <crypt.h>
#include <iostream>

#include "mkcert.c"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

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
    char buffer[10000];
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

std::string get_method(const std::string& message)
{
	// Method is stored after content-length line, via 'Method:'
	const char* method_line = strcasestr(&message[0], "Method: "); 
	if (method_line == nullptr) {
		return "";
	}
	// Only methods are: getcert, changepw, sendmsg, recvmsg
	// Note, 3 of them are length 7, and changepw is length 8
	
	std::string method = std::string(method_line).substr(8, 8); 
	return method;
}

std::string get_content(const std::string& content, const std::string& message)
{

	const char* break_line = strcasestr(&message[0], "\r\n\r\n");
        const char* body = break_line + 4;
	const char* content_line = strcasestr(body, content.c_str());

	if (content_line == nullptr) {
		return "";
	}

	std::string c_s = std::string(content_line);
	int l = content.length();	
	std::string content_value = c_s.substr(l, c_s.find("\r\n")-l);
	return content_value;

}

std::string login(std::string username, std::string password)
{
	// Check if username exists
	std::fstream file;
	std::string filename = "hashed_passwords/" + username + ".txt";
   	
	file.open(filename, std::ios::in);  
   	if(!file.is_open()) //checking whether the file is open
   	{
		return "Username not found";
      	}
	
	std::string hashed_password;
      	getline(file, hashed_password);  // Should only be one line
        file.close();
                           
	char* c = crypt(password.c_str(), hashed_password.c_str());
	
	if (strcmp(c, hashed_password.c_str()) != 0) 
	{
		return "Incorrect Password";
	}

	return "Login Success";
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

void write_new_pass(std::string username, char* newpass)
{
	std::fstream file;
	std::string filename = "hashed_passwords/" + username + ".txt";
   	
	file.open(filename, std::ios::out); 
        file << newpass << "\n";	
        file.close();
}
void generate_bad_request_error(std::string message, std::string& body, std::string& header)
{
	body += message + "\r\n\r\n";
	header += "HTTP/1.1 400 Bad Request\r\n";
	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
}

void generate_internal_error(std::string message, std::string& body, std::string& header)
{
	body += message + "\r\n\r\n";
	header += "HTTP/1.1 500 Internal Server Error\r\n";
	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
}

int verify_the_certificate(SSL *ssl, std::string& user)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
        return 1;
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        fprintf(stderr, "No certificate was presented by the client\n");
        return 1;
    }

    return 0;
}

void send_certificate_error_response(BIO *bio)
{
	std::string body = "Could not verify certificate\r\n\r\n";
	std::string header = "HTTP/1.1 401 Unauthorized\r\n";
	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	
	BIO_write(bio, header.data(), header.size());
	BIO_write(bio, body.data(), body.size());
	BIO_flush(bio);

}
void send_http_response(BIO *bio, const std::string& message, std::string method)
{
    std::string body = "";
    std::string header = "";

    if (method == "") {generate_bad_request_error("Method option not found", body, header);}

    else if (method.substr(0,7) == "getcert"){
	    
	    std::string user = get_content("Username: ", message);
	    if (user == "") {generate_bad_request_error("Username in body not found", body, header); goto write;}
	    std::string pass = get_content("Password: ", message);
	    if (pass == "") {generate_bad_request_error("Password in body not found", body, header); goto write;}
	    std::string pubkey = get_content("Public Key: ", message);
	    if (pubkey == "") {generate_bad_request_error("Public Key in body not found", body, header); goto write;}
	    
	    std::string login_result = login(user, pass);	
	    if(login_result != "Login Success")
	    {
	    
		    body += login_result + "\r\n\r\n";
		    header += "HTTP/1.1 401 Unauthorized\r\n";
		    header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	    }
	    
	    else // Successful login, so generate a certificate
	    {
		// Get the public key
		BIO* pkey_bio = BIO_new(BIO_s_mem());
		EVP_PKEY* pkey;
	
		BIO_puts(pkey_bio, pubkey.c_str());
		pkey = PEM_read_bio_PUBKEY(pkey_bio, NULL, NULL, NULL);

		BIO* cert_bio = BIO_new(BIO_s_mem());
		std::string result = mkcert(cert_bio, pkey, user.c_str());
	
		if (result != "Success")
		{
			printf(result.c_str());
			generate_internal_error("Error in generating certificate", body, header);
			goto write;	
		}

		BUF_MEM *bio_buf;
    		BIO_get_mem_ptr(cert_bio, &bio_buf);
		std::string cert  = std::string(bio_buf->data, bio_buf->length);
		
		// Server also saves cert
		std::ofstream cert_file;
	    	std::string filename = "clientcerts/";
	    	filename += user;
	    	filename += ".cert.pem";
	    	cert_file.open(filename.c_str());
	    	cert_file << cert;
	    	cert_file.close();

		body += cert + "\r\n";
		header += "HTTP/1.1 200 OK\r\n";
    		header += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    		header += "\r\n";
	    }	
    }
    else if (method.substr(0,8) == "changepw")
    {
	    std::string user = get_content("Username: ", message);
	    if (user == "") {generate_bad_request_error("Username in body not found", body, header); goto write;}
	    std::string pass = get_content("Password: ", message);
	    if (pass == "") {generate_bad_request_error("Password in body not found", body, header); goto write;}
	    std::string newpass = get_content("New Password: ", message);
	    if (newpass == "") {generate_bad_request_error("New Password in body not found", body, header); goto write;}
	    
	    std::string login_result = login(user, pass);	
	    if(login_result != "Login Success")
	    {
		    body += login_result + "\r\n\r\n";
		    header += "HTTP/1.1 401 Unauthorized\r\n";
		    header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	    }
	    
	    else // Successful login, so generate a new password
	    {
		unsigned long seed[2];
  		char salt[] = "$6$........";
  		const char *const seedchars =
  			"./0123456789ABCDEFGHIJKLMNOPQRST"
  			"UVWXYZabcdefghijklmnopqrstuvwxyz";
  		char *password;
  		int i;
  		seed[0] = time(NULL);
  		seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

  		for (i=0; i<8; i++)
    			salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

  		password = crypt(newpass.c_str(), salt);
		write_new_pass(user, password);

	    	body += "Password updated\r\n\r\n";
	    	header += "HTTP/1.1 200 OK\r\n";
	    	header += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	    	header += "\r\n";
	    }
    }
    else if (method.substr(0,7) == "sendmsg")
    {
	    std::string cert = get_content("Certificate: ", message);
	    if (cert == "") {generate_bad_request_error("Certificate in body not found", body, header); goto write;}
	    
            // Convert certificate string to X509, so we can extract the commonname
	    BIO *cbio;
	    X509 *certificate;
	    
	    cbio = BIO_new(BIO_s_mem());
	    BIO_puts(cbio, cert.c_str());
	    certificate = PEM_read_bio_X509(cbio, NULL, NULL, NULL);

	    X509_NAME *subj = X509_get_subject_name(certificate);
	    char cn[1024];

            int name_len = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
            if (name_len == -1) {

		    	body += "Unable to locate certificate CN\r\n\r\n";
		    	header += "HTTP/1.1 401 Unauthorized\r\n";
		    	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
			goto write;

            } else if (name_len != (int)strlen(cn)) {

			body += "Certificate CN= is malformed\r\n\r\n";
		    	header += "HTTP/1.1 401 Unauthorized\r\n";
		    	header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
			goto write;
            }

	    // Find the certificate file, if it exists
	    std::fstream file;
	    std::string filename = "clientcerts/" + std::string(cn) + ".cert.pem";
   	
	    file.open(filename, std::ios::in);  
   	    if(!file.is_open()) //checking whether the file is open
   	    {
		body += "Certificate not found in database - user does not exist\r\n\r\n";
		header += "HTTP/1.1 401 Unauthorized\r\n";
		header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		goto write;
      	    }

	    std::string line;
	    std::string cert_to_verify;
	     
	    while(getline(file, line))
	    	{cert_to_verify += line + "\n";}
	    file.close();

	    cert_to_verify = cert_to_verify.substr(0,cert_to_verify.size()-1);
	    
	    if (cert_to_verify != cert)
	    {
	    	body += "Certificate verification failed\r\n\r\n";
		header += "HTTP/1.1 401 Unauthorized\r\n";
		header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		goto write;

	    }

	    /* TODO: Now that cert is valid, proceed with sending the message */
	    body += cn;
	    body +="\r\n\r\n";
	    header += "HTTP/1.1 200 OK\r\n";
	    header += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    }

write:
    BIO_write(bio, header.data(), header.size());
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

    if (SSL_CTX_use_certificate_file(ctx.get(), "certs/localhost.cert.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "key/localhost.key.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server private key");
    }

    if (!SSL_CTX_load_verify_locations(ctx.get(),"../certificates/root/ca/intermediate/certs/ca-chain.cert.pem",NULL)) {
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
	    
	    if (BIO_do_handshake(bio.get()) <= 0)
	    {
		    printf("Error in bio handshake");
		    continue;
	    }
            std::string request = my::receive_http_message(bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());
	    std::string method = my::get_method(request);
    	    
	    my::send_http_response(bio.get(), request, method);
        } catch (const std::exception& ex) {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}
