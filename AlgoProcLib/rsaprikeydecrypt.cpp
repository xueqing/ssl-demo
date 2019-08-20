#include "rsaprikeydecrypt.h"

#include <string.h>

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

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);

    do
    {
        if(!(m_pubKey = RSA_new()))
        {
            fprintf(stderr, "%s() failed to new RSA\n", __func__);
            break;
        }

        if(LoadPriKey(param.filePath) != AlgoProcLib::RES_OK)
            break;

        int inLen = param.strIn.length();
        unsigned char *inBuf = reinterpret_cast<unsigned char*>(const_cast<char*>(param.strIn.c_str()));

        int outLen =  RSA_size(m_priKey);

        printf("%s() Begin RSA_private_decrypt ...\n", __func__);
        nret =  RSA_private_decrypt(inLen, inBuf, outBuf, m_priKey, RSA_PKCS1_PADDING/*RSA_NO_PADDING*/);
        printf("%s() After RSA_private_decrypt ...\n", __func__);

        param.lenOut = outLen;
        param.strOut = string(reinterpret_cast<char*>(outBuf), outLen);
        nret = RES_OK;
    }while(false);

    return nret;
}
