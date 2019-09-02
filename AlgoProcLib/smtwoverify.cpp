#include "smtwoverify.h"

#include <string.h>
#include <openssl/evp.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

SMTwoVerify::SMTwoVerify()
    : SMTwoCrypt()
{

}

SMTwoVerify::~SMTwoVerify()
{
}

int SMTwoVerify::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    EVP_PKEY *pkey = nullptr;
    EVP_MD_CTX *mdctx = nullptr;

    do
    {
        if(!(pkey = EVP_PKEY_new()))
        {
            fprintf(stderr, "%s() failed to call EVP_PKEY_new\n", __func__);
            break;
        }

        if(LoadPubKey(m_strSM2KeyPath, &pkey) != AlgoProcLib::RES_OK)
            break;

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        int lenSign = Base64Decode(buf64, param.strOut.c_str());
        unsigned char *sign = reinterpret_cast<unsigned char*>(buf64);

        if(!(mdctx=EVP_MD_CTX_create()))
        {
            fprintf(stderr, "%s() failed to call EVP_MD_CTX_create\n", __func__);
            break;
        }
        // kiki: use EVP_sm3() instead of EVP_sha256(), new version support the latter
        if(!EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyInit\n", __func__);
            break;
        }
        if(!EVP_DigestVerifyUpdate(mdctx, param.strIn.c_str(), param.strIn.length()))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyUpdate\n", __func__);
            break;
        }

        if(!EVP_DigestVerifyFinal(mdctx, sign, lenSign))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyFinal\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);

    return nret;
}
