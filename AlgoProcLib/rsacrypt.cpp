#include "rsacrypt.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;
using namespace KMS;

RSACrypt::RSACrypt()
    : AlgoProcLib()
{

}

RSACrypt::~RSACrypt()
{
}

int RSACrypt::LoadPubKey(string &filePath, RSA **pubKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_pub.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to read %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_read_bio_RSAPublicKey(pBio, pubKey, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_RSAPublicKey from %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() read rsa pub key success\n", __func__);

//        RSA_print_fp(stdout, pubKey, 11);
        nret = RES_OK;
    }while(false);

    BIO_free(pBio);

    return nret;
}

int RSACrypt::LoadPriKey(string &filePath, RSA **priKey)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_pri.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to read %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_read_bio_RSAPrivateKey(pBio, priKey, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_RSAPrivateKey from %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() read rsa pri key success\n", __func__);

//        RSA_print_fp(stdout, priKey, 11);
        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}

int RSACrypt::SavePubKey(string &filePath, RSA *pRsa)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_pub.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to write %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_write_bio_RSAPublicKey(pBio, pRsa))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_RSAPublicKey to %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() save rsa pub key success\n", __func__);

//        RSA_print_fp(stdout, pRsa, 11);
        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}

int RSACrypt::SavePriKey(string &filePath, RSA *pRsa)
{
    int nret = RES_SERVER_ERROR;

    BIO *pBio = nullptr;
    do
    {
        string keyPath = filePath + "_pri.pem";
        if(!(pBio = BIO_new_file(keyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file to write %s\n", __func__, keyPath.c_str());
            break;
        }
        if(!PEM_write_bio_RSAPrivateKey(pBio, pRsa,  nullptr, nullptr, 0, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_RSAPrivateKey to %s\n", __func__, keyPath.c_str());
            break;
        }
        printf( "%s() save rsa pri key success\n", __func__);

//        RSA_print_fp(stdout, pRsa, 11);
        nret = RES_OK;
    }while(false);
    BIO_free(pBio);

    return nret;
}
