#!/bin/bash

set -e
ROOTDIR=./root
# Check if ./root exists. If so, we need to override with new config.
if [[ -d "$ROOTDIR" ]]
then
	rm -rf $ROOTDIR
    	echo "--- $ROOTDIR deleted."
fi

echo "# --- GENERATING ROOT CA --------------------------- #"
# Create the Directories
mkdir root
mkdir root/ca
R=./root/ca

mkdir $R/certs $R/newcerts $R/private
chmod 700 $R/private
touch $R/index.txt
echo 1000 > $R/serial
echo "$R directory and internal files created."
echo ''

echo "# --- CREATING CONFIG FILE ------------------------- #"
echo '# OpenSSL root CA configuration file.
# Copy to `/root/ca/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ./root/ca
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = New York
localityName_default            = Brooklyn
0.organizationName_default      = Michaels Club
organizationalUnitName_default  = 
emailAddress_default            = mg3856@columbia.edu

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign' > $R/openssl.cnf

echo "$R/openssl.cnf configuration file created"
echo ''
# --------------------------------------------------------------# 

echo "# --- GENERATING ROOT KEY -------------------------- #"
# Generate the root key and certificate #
openssl genrsa -aes256 -out $R/private/ca.key.pem 4096
chmod 400 $R/private/ca.key.pem
echo 'CA Private Key Created'
echo ''

echo "# ---  GENERATING ROOT CERTIFICATE ----------------- #"
openssl req -config $R/openssl.cnf \
      -key $R/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out $R/certs/ca.cert.pem

chmod 444 $R/certs/ca.cert.pem
echo 'CA Private Certificate Created:'
openssl x509 -noout -text -in $R/certs/ca.cert.pem
echo ''

echo "# --- CREATING INTERMEDIATE ------------------------ #"

RI=$R/intermediate

mkdir $RI
mkdir $RI/certs $RI/csr $RI/newcerts $RI/private
chmod 700 $RI/private
touch $RI/index.txt
echo 1000 > $RI/serial

echo "$RI directory and internal files created"
echo ''

echo "# --- GENERATING INTERMEDIATE CONFIG  -------------- #"

echo '# OpenSSL intermediate CA configuration file.
# Copy to `/root/ca/intermediate/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ./root/ca/intermediate
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem


# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = New York
localityName_default            = Brooklyn
0.organizationName_default      = Michaels Club
organizationalUnitName_default  =
emailAddress_default            = 

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = critical, clientAuth

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = critical, serverAuth
subjectAltName = @alt_names

[ encrypt_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, keyAgreement, encipherOnly

[ sign_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature

[alt_names]
DNS.1 = localhost' > $RI/openssl.cnf


echo "$RI/openssl.cnf configuration created"
echo ''
# ------------ GENERATING INTEMEDIATE KEY AND CERFICIATE ---------------#

echo '# --- GENERATING INTERMEDIATE KEY ------------------ #'
openssl genrsa -aes256 \
      -out $RI/private/intermediate.key.pem 4096

chmod 400 $RI/private/intermediate.key.pem
echo 'Private intermediate key created'
echo ''

echo '# --- GENERATING INTERMEDIATE CERTIFICATE REQUEST -- #'
openssl req -config $RI/openssl.cnf -new -sha256 \
      -key $RI/private/intermediate.key.pem \
      -out $RI/csr/intermediate.csr.pem

echo 'Intermediate certificate Signing Request  created '
echo ''

echo '# --- SIGNING INTERMEDIATE CERFICATE WITH CA ------- #'
# Signing the certificate with CA
openssl ca -config $R/openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in $RI/csr/intermediate.csr.pem \
      -out $RI/certs/intermediate.cert.pem

chmod 444 $RI/certs/intermediate.cert.pem

echo "Intermediate Cerficate signed and created:"
echo ''

echo '# --- VERIFYING INTERMEDIATE CA -------------------- #'

openssl x509 -noout -text \
      -in $RI/certs/intermediate.cert.pem
echo ''
echo 'Verifiying Intermediate CA'
openssl verify -CAfile $R/certs/ca.cert.pem \
      $RI/certs/intermediate.cert.pem
echo ''
echo 'Verfiying Intermediate Certificate added to CA index'
cat $R/index.txt
echo ''

cat $RI/certs/intermediate.cert.pem \
      $R/certs/ca.cert.pem > $RI/certs/ca-chain.cert.pem

chmod 444 $RI/certs/ca-chain.cert.pem

echo 'Certificate Chain created'
