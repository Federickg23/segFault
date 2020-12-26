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

const char* mkcert(BIO* cert_bio, X509_REQ* certreq) {

  ASN1_INTEGER                 *aserial = NULL;
  EVP_PKEY                     *ca_privkey, *req_pubkey;
  EVP_MD                       const *digest = NULL;
  X509                         *newcert, *cacert;
  X509_NAME                    *name;
  X509V3_CTX                   ctx;
  FILE                         *fp;
  long                         valid_secs = 31536000;

   // These function calls initialize openssl for correct work.  *
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();


  /* -------------------------------------------------------- *
   * Load ithe signing CA Certificate file                    *
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
  X509_free(newcert);
  return "Success";
}
