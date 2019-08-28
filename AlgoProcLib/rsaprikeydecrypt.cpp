#include "rsaprikeydecrypt.h"

#include <string.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

RSAPrikeyDecrypt::RSAPrikeyDecrypt()
    : RSACrypt()
{

}

RSAPrikeyDecrypt::~RSAPrikeyDecrypt()
{
}

int RSAPrikeyDecrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    RSA *priKey = nullptr;

    do
    {
        if(!(priKey = RSA_new()))
        {
            fprintf(stderr, "%s() failed to new RSA\n", __func__);
            break;
        }

        if(LoadPriKey(m_strRSAKeyPath, &priKey) != AlgoProcLib::RES_OK)
            break;

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        int len64 = Base64Decode(buf64, param.strIn.c_str());

        unsigned char outBuf[MAX_BUF_SIZE];
        memset(outBuf, 0, MAX_BUF_SIZE);
        unsigned char *inBuf = reinterpret_cast<unsigned char*>(buf64);
        param.lenOut =  RSA_private_decrypt(len64, inBuf, outBuf, priKey, RSA_PKCS1_PADDING/*RSA_NO_PADDING*/);
        if(param.lenOut == -1)
        {
            fprintf(stderr, "%s() RSA_private_decrypt error ...\n", __func__);
            break;
        }
        param.strOut = string(reinterpret_cast<char*>(outBuf), param.lenOut);

        nret = RES_OK;
    }while(false);

    RSA_free(priKey);

    return nret;
}
