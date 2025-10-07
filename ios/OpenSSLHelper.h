#ifndef OpenSSLHelper_h
#define OpenSSLHelper_h

#include <openssl/x509.h>
#include <openssl/evp.h>

X509_NAME *create_x509_name(void);
int add_x509_name_entry(X509_NAME *name, const char *field, const char *value);
X509_REQ *create_x509_request(void);
int set_public_key(X509_REQ *req, unsigned char *pubkey, int len);
int set_subject_name(X509_REQ *req, X509_NAME *name);
int sign_x509_request(X509_REQ *req, EVP_PKEY *pkey);
unsigned char *export_csr_to_der(X509_REQ *req, int *len);
void cleanup_x509_request(X509_REQ *req);
void cleanup_evp_pkey(EVP_PKEY *pkey);
void cleanup_x509_name(X509_NAME *name);
EVP_PKEY *convert_to_evp_pkey(unsigned char *key, int len, int is_private);

#endif