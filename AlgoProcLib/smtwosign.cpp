#include "smtwosign.h"

#include <string.h>
#include <openssl/evp.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

SMTwoSign::SMTwoSign()
    : SMTwoCrypt()
{

}

SMTwoSign::~SMTwoSign()
{
}

int SMTwoSign::ProcessAlgorithm(AlgorithmParams &param)
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

        if(LoadPriKey(m_strSM2KeyPath, &pkey) != AlgoProcLib::RES_OK)
            break;

        unsigned char sign[MAX_BUF_SIZE];
        memset(sign, 0, MAX_BUF_SIZE);

        if(!(mdctx=EVP_MD_CTX_create()))
        {
            fprintf(stderr, "%s() failed to call EVP_MD_CTX_create\n", __func__);
            break;
        }
        // kiki: use EVP_sm3() instead of EVP_sha256(), new version support the latter
        if(!EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignInit\n", __func__);
            break;
        }
        if(!EVP_DigestSignUpdate(mdctx, param.strIn.c_str(), param.strIn.length()))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignUpdate\n", __func__);
            break;
        }

        size_t lenout = 0;
        if(!EVP_DigestSignFinal(mdctx, nullptr, &lenout))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignFinal\n", __func__);
            break;
        }
        if(!EVP_DigestSignFinal(mdctx, sign, &lenout))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignFinal\n", __func__);
            break;
        }

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        param.lenOut = Base64Encode(buf64, reinterpret_cast<char*>(sign), lenout);
        param.strOut = string(buf64, param.lenOut);

        nret = RES_OK;
    }while(false);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);

    return nret;
}
