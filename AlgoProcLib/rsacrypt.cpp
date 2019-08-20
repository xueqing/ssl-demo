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
    CloseKey();
    FreeRes();
}

int RSACrypt::LoadPubKey(string &filePath)
{
    int nret = RES_SERVER_ERROR;

    BIO *pPubBio = nullptr;
    do
    {
        string pubKeyPath = filePath + "_pub.pem";
        if(!(pPubBio = BIO_new_file(pubKeyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file\n", __func__);
            break;
        }
        if(!PEM_read_bio_RSAPublicKey(pPubBio, &m_pubKey, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_RSAPublicKey\n", __func__);
            break;
        }
        printf( "%s() read rsa pub key from %s\n", __func__, pubKeyPath.c_str());

        RSA_print_fp(stdout, m_pubKey, 11);

        nret = RES_OK;
    }while(false);

    BIO_free(pPubBio);

    return nret;
}

int RSACrypt::LoadPriKey(string &filePath)
{
    int nret = RES_SERVER_ERROR;

    BIO *pPriBio = nullptr;
    do
    {
        string priKeyPath = filePath + "_pri.pem";
        if(!(pPriBio = BIO_new_file(priKeyPath.c_str(), "rb")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file\n", __func__);
            break;
        }
        if(!PEM_read_bio_RSAPrivateKey(pPriBio, &m_priKey, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_read_bio_RSAPrivateKey\n", __func__);
            break;
        }
        printf( "%s() read rsa pri key from %s\n", __func__, priKeyPath.c_str());

        RSA_print_fp(stdout, m_priKey, 11);

        nret = RES_OK;
    }while(false);

    BIO_free(pPriBio);

    return nret;
}

int RSACrypt::CloseKey()
{
    if(m_pubKey)
    {
        RSA_free(m_pubKey);
        m_pubKey = nullptr;
    }

    if(m_priKey)
    {
        RSA_free(m_priKey);
        m_priKey = nullptr;
    }

    return 0;
}

void RSACrypt::FreeRes()
{
    if(m_pubExpd)
    {
        delete [] m_pubExpd;
        m_pubExpd = nullptr;
    }
    if(m_priExpd)
    {
        delete [] m_priExpd;
        m_priExpd = nullptr;
    }
    if(m_module)
    {
        delete [] m_module;
        m_module = nullptr;
    }
}
