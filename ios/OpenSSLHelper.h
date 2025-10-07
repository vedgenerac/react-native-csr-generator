#ifndef OpenSSLHelper_h
#define OpenSSLHelper_h

#include
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

// Create and manage X509 request
X509_REQ *create_x509_request(void);
void cleanup_x509_request(X509_REQ *req);

// Create and manage X509 name
X509_NAME *create_x509_name(void);
void cleanup_x509_name(X509_NAME *name);
int add_x509_name_entry(X509_NAME *name, const char *field, const char *value);

// Key management
EVP_PKEY *convert_to_evp_pkey(const unsigned char *key_data, int key_len, int is_private);
void cleanup_evp_pkey(EVP_PKEY *pkey);

// Set public key and subject name
int set_public_key(X509_REQ *req, const unsigned char *pub_key_data, int pub_key_len);
int set_subject_name(X509_REQ *req, X509_NAME *name);

// Sign and export
int sign_x509_request(X509_REQ *req, EVP_PKEY *pkey);
unsigned char *export_csr_to_der(X509_REQ *req, int *out_len);

#endif /* OpenSSLHelper_h */