#include "rsaverify.h"

#include <string.h>
#include <openssl/evp.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

RSAVerify::RSAVerify()
    : RSACrypt()
{

}

RSAVerify::~RSAVerify()
{
}

int RSAVerify::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    RSA *rsa = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_MD_CTX *mdctx = nullptr;

    do
    {
        if(!(rsa = RSA_new()))
        {
            fprintf(stderr, "%s() failed to new RSA\n", __func__);
            break;
        }

        if(!(pkey = EVP_PKEY_new()))
        {
            fprintf(stderr, "%s() failed to call EVP_PKEY_new\n", __func__);
            break;
        }

        if(LoadPubKey(m_strRSAKeyPath, &rsa) != AlgoProcLib::RES_OK)
            break;

        EVP_PKEY_assign_RSA(pkey, rsa);

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        int lenSign = Base64Decode(buf64, param.strOut.c_str());
        unsigned char *sign = reinterpret_cast<unsigned char*>(buf64);

        if(!(mdctx=EVP_MD_CTX_create()))
        {
            fprintf(stderr, "%s() failed to call EVP_MD_CTX_create\n", __func__);
            break;
        }
        if(!EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyInit\n", __func__);
            break;
        }
        rsa = nullptr;
        pkey = nullptr;
        if(!EVP_DigestVerifyUpdate(mdctx, param.strIn.c_str(), param.strIn.length()))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyUpdate\n", __func__);
            break;
        }

        int ver = EVP_DigestVerifyFinal(mdctx, sign, lenSign);
        if(ver == 1)
        {
            printf("%s() EVP_DigestVerifyFinal verify success\n", __func__);
        }
        else if(ver == 0)
        {
            fprintf(stderr, "%s() EVP_DigestVerifyFinal failure\n", __func__);
            break;
        }
        else
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyFinal\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);

    return nret;
}
