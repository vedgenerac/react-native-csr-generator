#include "OpenSSLHelper.h"
#include
#include

X509_REQ *create_x509_request(void)
{
    X509_REQ *req = X509_REQ_new();
    if (req)
    {
        X509_REQ_set_version(req, 0L);
    }
    return req;
}

void cleanup_x509_request(X509_REQ *req)
{
    if (req)
    {
        X509_REQ_free(req);
    }
}

X509_NAME *create_x509_name(void)
{
    return X509_NAME_new();
}

void cleanup_x509_name(X509_NAME *name)
{
    if (name)
    {
        X509_NAME_free(name);
    }
}

int add_x509_name_entry(X509_NAME *name, const char *field, const char *value)
{
    if (!name || !field || !value)
    {
        return 0;
    }
    return X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                      (const unsigned char *)value, -1, -1, 0);
}

EVP_PKEY *convert_to_evp_pkey(const unsigned char *key_data, int key_len, int is_private)
{
    if (!key_data || key_len <= 0)
    {
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (is_private)
    {
        // Set private key (32 bytes for P-256)
        BIGNUM *priv_bn = BN_bin2bn(key_data, key_len, NULL);
        if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn))
        {
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        BN_free(priv_bn);

        // Compute public key from private key
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        EC_POINT *pub_point = EC_POINT_new(group);
        if (!pub_point || !EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL))
        {
            EC_POINT_free(pub_point);
            EC_KEY_free(ec_key);
            EVP_PKEY_free(pkey);
            return NULL;
        }

        if (!EC_KEY_set_public_key(ec_key, pub_point))
        {
            EC_POINT_free(pub_point);
            EC_KEY_free(ec_key);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        EC_POINT_free(pub_point);
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

void cleanup_evp_pkey(EVP_PKEY *pkey)
{
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
}

int set_public_key(X509_REQ *req, const unsigned char *pub_key_data, int pub_key_len)
{
    if (!req || !pub_key_data || pub_key_len != 64)
    {
        return 0;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
    {
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *point = EC_POINT_new(group);
    if (!point)
    {
        EC_KEY_free(ec_key);
        return 0;
    }

    // Convert raw 64-byte key to uncompressed point (0x04 || X || Y)
    unsigned char uncompressed[65];
    uncompressed[0] = 0x04;
    memcpy(uncompressed + 1, pub_key_data, 64);

    if (!EC_POINT_oct2point(group, point, uncompressed, 65, NULL))
    {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        return 0;
    }

    if (!EC_KEY_set_public_key(ec_key, point))
    {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        return 0;
    }
    EC_POINT_free(point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        return 0;
    }

    int result = X509_REQ_set_pubkey(req, pkey);
    EVP_PKEY_free(pkey);

    return result;
}

int set_subject_name(X509_REQ *req, X509_NAME *name)
{
    if (!req || !name)
    {
        return 0;
    }
    return X509_REQ_set_subject_name(req, name);
}

int sign_x509_request(X509_REQ *req, EVP_PKEY *pkey)
{
    if (!req || !pkey)
    {
        return 0;
    }
    return X509_REQ_sign(req, pkey, EVP_sha256());
}

unsigned char *export_csr_to_der(X509_REQ *req, int *out_len)
{
    if (!req || !out_len)
    {
        return NULL;
    }

    int len = i2d_X509_REQ(req, NULL);
    if (len <= 0)
    {
        return NULL;
    }

    unsigned char *der = (unsigned char *)malloc(len);
    if (!der)
    {
        return NULL;
    }

    unsigned char *p = der;
    int actual_len = i2d_X509_REQ(req, &p);
    if (actual_len <= 0)
    {
        free(der);
        return NULL;
    }

    *out_len = actual_len;
    return der;
}