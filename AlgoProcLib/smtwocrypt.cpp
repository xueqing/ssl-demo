#include "smtwocrypt.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;
using namespace KMS;

SMTwoCrypt::SMTwoCrypt()
    : AlgoProcLib()
{

}

SMTwoCrypt::~SMTwoCrypt()
{
}

int SMTwoCrypt::LoadPubKey(string &filePath, EVP_PKEY **pubKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_ec.pub";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to read %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!(*pubKey=PEM_read_bio_PUBKEY(pBio, nullptr, 0, nullptr)))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_PUBKEY from %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() read sm2 pub key success\n", __func__);

        nret = RES_OK;
    }while(false);

    BIO_free(pBio);

    return nret;
}

int SMTwoCrypt::LoadPriKey(string &filePath, EVP_PKEY **priKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_ec.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to read %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!(*priKey=PEM_read_bio_PrivateKey(pBio, nullptr, 0, nullptr)))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_PrivateKey from %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() read sm2 pri key success\n", __func__);

        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}

int SMTwoCrypt::SavePubKey(string &filePath, EC_KEY *pKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_ec.pub";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to write %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_write_bio_EC_PUBKEY(pBio, pKey))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_EC_PUBKEY to %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() save sm2 pub key success\n", __func__);

        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}

int SMTwoCrypt::SavePriKey(string &filePath, EC_KEY *pKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_ec.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to write %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_write_bio_ECPrivateKey(pBio, pKey,  nullptr, nullptr, 0, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_ECPrivateKey to %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() save sm2 pri key success\n", __func__);

        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}
