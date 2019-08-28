#include "rsapubkeyencrypt.h"

#include <string.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

RSAPubkeyEncrypt::RSAPubkeyEncrypt()
    : RSACrypt()
{

}

RSAPubkeyEncrypt::~RSAPubkeyEncrypt()
{
}

int RSAPubkeyEncrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    RSA *pubKey = nullptr;

    do
    {
        if(!(pubKey = RSA_new()))
        {
            fprintf(stderr, "%s() failed to new RSA\n", __func__);
            break;
        }

        if(LoadPubKey(m_strRSAKeyPath, &pubKey) != AlgoProcLib::RES_OK)
            break;

        unsigned char outBuf[MAX_BUF_SIZE];
        memset(outBuf, 0, MAX_BUF_SIZE);
        unsigned char *inBuf = reinterpret_cast<unsigned char*>(const_cast<char*>(param.strIn.c_str()));
        int outLen =  RSA_public_encrypt(param.strIn.length(), inBuf, outBuf, pubKey, RSA_PKCS1_PADDING/*RSA_NO_PADDING*/);
        if(outLen == -1)
        {
            fprintf(stderr, "%s() RSA_public_encrypt error ...\n", __func__);
            break;
        }

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        char *buf = reinterpret_cast<char*>(outBuf);
        param.lenOut = Base64Encode(buf64, buf, outLen);
        param.strOut = string(buf64, param.lenOut);

        nret = RES_OK;
    }while(false);

    RSA_free(pubKey);

    return nret;
}
