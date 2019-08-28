#include "symmkeygenerator.h"

#include <string.h>

#include <openssl/rand.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

SymmKeyGenerator::SymmKeyGenerator()
    : AlgoProcLib()
{

}

int SymmKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    do
    {
        if(m_lenSymmKey > MAX_BUF_SIZE)
        {
            fprintf(stderr, "%s() len overflow\n", __func__);
            break;
        }

        unsigned char outBuf[MAX_BUF_SIZE];
        memset(outBuf, 0, MAX_BUF_SIZE);
        if(RAND_bytes(outBuf, m_lenSymmKey) <= 0)
        {
            fprintf(stderr, "%s() generate random bytes error\n", __func__);
            break;
        }

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        char *buf = reinterpret_cast<char*>(outBuf);
        param.lenOut = Base64Encode(buf64, buf, m_lenSymmKey);
        param.symmKey = string(buf64, param.lenOut);

        nret = RES_OK;
    }while(false);

    return nret;
}
