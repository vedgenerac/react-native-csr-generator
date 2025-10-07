#include "OpenSSLHelper.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>

X509_NAME *create_x509_name(void)
{
    X509_NAME *name = X509_NAME_new();
    if (!name)
    {
        fprintf(stderr, "X509_NAME_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return name;
}

int add_x509_name_entry(X509_NAME *name, const char *field, const char *value)
{
    int result = X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8, (unsigned char *)value, -1, -1, 0);
    if (!result)
    {
        fprintf(stderr, "X509_NAME_add_entry_by_txt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}

X509_REQ *create_x509_request(void)
{
    X509_REQ *req = X509_REQ_new();
    if (!req)
    {
        fprintf(stderr, "X509_REQ_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return req;
}

int set_public_key(X509_REQ *req, unsigned char *pubkey, int len)
{
    fprintf(stderr, "Setting public key, length: %d\n", len);
    int adjusted_len = len;
    unsigned char *adjusted_pubkey = pubkey;

    // Handle uncompressed format: skip 0x04 prefix if present
    if (len == 65 && pubkey[0] == 0x04)
    {
        adjusted_pubkey += 1;
        adjusted_len = 64;
        fprintf(stderr, "Adjusted public key to 64 bytes (skipped 0x04 prefix)\n");
    }
    else if (len != 64)
    {
        fprintf(stderr, "Invalid public key length: %d, expected 64 or 65 (with 0x04)\n", len);
        return 0;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    BIGNUM *x = BN_bin2bn(adjusted_pubkey, 32, NULL);
    BIGNUM *y = BN_bin2bn(adjusted_pubkey + 32, 32, NULL);
    if (!x || !y)
    {
        fprintf(stderr, "BN_bin2bn failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return 0;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y))
    {
        fprintf(stderr, "EC_KEY_set_public_key_affine_coordinates failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return 0;
    }
    BN_free(x);
    BN_free(y);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        return 0;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        fprintf(stderr, "EVP_PKEY_assign_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return 0;
    }

    int result = X509_REQ_set_pubkey(req, pkey);
    if (!result)
    {
        fprintf(stderr, "X509_REQ_set_pubkey failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    EVP_PKEY_free(pkey);
    return result;
}

int set_subject_name(X509_REQ *req, X509_NAME *name)
{
    int result = X509_REQ_set_subject_name(req, name);
    if (!result)
    {
        fprintf(stderr, "X509_REQ_set_subject_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}

int sign_x509_request(X509_REQ *req, EVP_PKEY *pkey)
{
    int result = X509_REQ_sign(req, pkey, EVP_sha256());
    if (!result)
    {
        fprintf(stderr, "X509_REQ_sign failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}

unsigned char *export_csr_to_der(X509_REQ *req, int *len)
{
    *len = i2d_X509_REQ(req, NULL);
    if (*len <= 0)
    {
        fprintf(stderr, "i2d_X509_REQ length calculation failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    unsigned char *buf = malloc(*len);
    if (!buf)
    {
        fprintf(stderr, "malloc failed for DER buffer\n");
        return NULL;
    }
    unsigned char *p = buf;
    i2d_X509_REQ(req, &p);
    return buf;
}

void cleanup_x509_request(X509_REQ *req)
{
    if (req)
        X509_REQ_free(req);
}

void cleanup_evp_pkey(EVP_PKEY *pkey)
{
    if (pkey)
        EVP_PKEY_free(pkey);
}

void cleanup_x509_name(X509_NAME *name)
{
    if (name)
        X509_NAME_free(name);
}

EVP_PKEY *convert_to_evp_pkey(unsigned char *key, int len, int is_private)
{
    if (!is_private)
    {
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&key, len);
        if (!pkey)
        {
            fprintf(stderr, "d2i_PUBKEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        return pkey;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        fprintf(stderr, "EVP_PKEY_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return NULL;
    }

    BIGNUM *priv_bn = BN_bin2bn(key, len, NULL);
    if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn))
    {
        fprintf(stderr, "EC_KEY_set_private_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    BN_free(priv_bn);

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        fprintf(stderr, "EVP_PKEY_assign_EC_KEY failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}