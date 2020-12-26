/* ------------------------------------------------------------ *
 * file:        certcreate.c                                    *
 * purpose:     Example code for creating OpenSSL certificates  *
 * author:      10/06/2012 Frank4DD                             *
 *                                                              *
 * gcc -o certcreate certcreate.c -lssl -lcrypto                *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

/*********** where is the ca certificate .pem file ****************************/
#define CACERT          "../certificates/root/ca/intermediate/certs/intermediate.cert.pem"
/*********** where is the ca's private key file *******************************/
#define CAKEY           "../certificates/root/ca/intermediate/private/intermediate.key.pem"
/*********** The password for the ca's private key ****************************/
#define PASS            (void *)"intermediate"

X509_REQ         *certreq = NULL;


X509_REQ *generate_cert_req(EVP_PKEY *p_key, const char* user) {
    X509_REQ 		*p_x509_req = NULL;
    X509_NAME		*x509_name = NULL;
    int				ret = 0;

    const char		*szCountry = "US";
    const char		*szProvince = "New York";
    const char		*szCity = "Brooklyn";
    const char		*szOrganization = "SegFault";
    const char		*szCommon = user;

    if (NULL == (p_x509_req = X509_REQ_new())) {
        printf("failed to create a new X509 REQ\n");
        goto CLEANUP;
    }

    if (0 > X509_REQ_set_pubkey(p_x509_req, p_key)) {
        printf("failed to set pub key\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(p_x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
	if (ret != 1){
		goto CLEANUP;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
	if (ret != 1){
		goto CLEANUP;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
	if (ret != 1){
		goto CLEANUP;
	}	

	ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
	if (ret != 1){
		goto CLEANUP;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
	if (ret != 1){
		goto CLEANUP;
	}

    if (0 > X509_REQ_sign(p_x509_req, p_key, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

CLEANUP:
    EVP_PKEY_free(p_key);

    return p_x509_req;
}


const char* mkcert(BIO* cert_bio, EVP_PKEY* pkey, const char* user) {

  ASN1_INTEGER                 *aserial = NULL;
  EVP_PKEY                     *ca_privkey, *req_pubkey;
  EVP_MD                       const *digest = NULL;
  X509                         *newcert, *cacert;
  X509_NAME                    *name;
  X509V3_CTX                   ctx;
  FILE                         *fp;
  long                         valid_secs = 31536000;

  RSA				*rsa = NULL;
  BIGNUM			*bne = NULL;   
  int				bits = 2048;
  unsigned long			e = RSA_F4;

	// These function calls initialize openssl for correct work.  *
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

	// 1. generate rsa key
	bne = BN_new();
	BN_set_word(bne,e);

	rsa = RSA_new();
	RSA_generate_key_ex(rsa, bits, bne, NULL);

  EVP_PKEY_assign_RSA(pkey, rsa);
  if (! (certreq = generate_cert_req(pkey, user))) {
   	return "Error can't read X509 request data into memory";
   }

  /* -------------------------------------------------------- *
   * Load in the signing CA Certificate file                    *
   * ---------------------------------------------------------*/
  if (! (fp=fopen(CACERT, "r"))) {
	  return "Error Reading CA cert file";
   }

  if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL))) {
	  return "Error loading CA cert into memory";
   }

  fclose(fp);

  /* -------------------------------------------------------- *
   * Import CA private key file for signing                   *
   * ---------------------------------------------------------*/
  ca_privkey = EVP_PKEY_new();

  if (! (fp = fopen (CAKEY, "r"))) {
	  return "Error reading CA private key file";
   }

  if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS))) {
	  return "Error importing key content from file";
   }

  fclose(fp);

  /* --------------------------------------------------------- *
   * Build Certificate with data from request                  *
   * ----------------------------------------------------------*/
  if (! (newcert=X509_new())) {
	  return "Error creating new X509 object";
   }

  if (X509_set_version(newcert, 2) != 1) {
	  return "Error setting certificate version";
   }

  /* --------------------------------------------------------- *
   * set the certificate serial number here                    *
   * If there is a problem, the value defaults to '0'          *
   * ----------------------------------------------------------*/
  aserial=ASN1_INTEGER_new();
  ASN1_INTEGER_set(aserial, 0);
  if (! X509_set_serialNumber(newcert, aserial)) {
    	return "Error setting serial number of the certificate";
   }

  /* --------------------------------------------------------- *
   * Extract the subject name from the request                 *
   * ----------------------------------------------------------*/
  if (! (name = X509_REQ_get_subject_name(certreq)))
	  return "Error getting subject from cert request";

  /* --------------------------------------------------------- *
   * Set the new certificate subject name                      *
   * ----------------------------------------------------------*/
  if (X509_set_subject_name(newcert, name) != 1) {
    	return "Error setting subject name of certificate";
   }

  /* --------------------------------------------------------- *
   * Extract the subject name from the signing CA cert         *
   * ----------------------------------------------------------*/
  if (! (name = X509_get_subject_name(cacert))) {
    	return "Error getting subject from CA certificate";
   }

  /* --------------------------------------------------------- *
   * Set the new certificate issuer name                       *
   * ----------------------------------------------------------*/
  if (X509_set_issuer_name(newcert, name) != 1) {
   	 return "Error setting issuer name of certificate";
   }

  /* --------------------------------------------------------- *
   * Extract the public key data from the request              *
   * ----------------------------------------------------------*/
  if (! (req_pubkey=X509_REQ_get_pubkey(certreq))) {
   	return "Error unpacking public key from request";
   }

  /* --------------------------------------------------------- *
   * Optionally: Use the public key to verify the signature    *
   * ----------------------------------------------------------*/
  if (X509_REQ_verify(certreq, req_pubkey) != 1) {
    	return "Error verifying signature on request";
   }

  /* --------------------------------------------------------- *
   * Set the new certificate public key                        *
   * ----------------------------------------------------------*/
  if (X509_set_pubkey(newcert, req_pubkey) != 1) {
    	return "Error setting public key of certificate";
   }

  /* ---------------------------------------------------------- *
   * Set X509V3 start date (now) and expiration date (+365 days)*
   * -----------------------------------------------------------*/
   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
      	return "Error setting start time";
   }

   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
      	return "Error setting expiration time";
   }

  /* ----------------------------------------------------------- *
   * Add X509V3 extensions                                       *
   * ------------------------------------------------------------*/
  X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);

  /* ----------------------------------------------------------- *
   * Set digest type, sign new certificate with CA's private key *
   * ------------------------------------------------------------*/
  digest = EVP_sha256();

  if (! X509_sign(newcert, ca_privkey, digest)) {
    	return "Error signing the new certificate";
  }

  /* ------------------------------------------------------------ *
   *  store the certificates                                      *
   * -------------------------------------------------------------*/
  if (! PEM_write_bio_X509(cert_bio, newcert)) {
   	return "Error storing the signed certificate";
   }

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */

  EVP_PKEY_free(req_pubkey);
  EVP_PKEY_free(ca_privkey);
  BN_free(bne);
  X509_free(newcert);
  X509_REQ_free(certreq);
  EVP_PKEY_free(pkey);

  return "Success";
}
