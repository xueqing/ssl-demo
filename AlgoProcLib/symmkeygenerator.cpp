#include "symmkeygenerator.h"

#include <string.h>

#include <openssl/rand.h>

using namespace std;
using namespace KMS;

SymmKeyGenerator::SymmKeyGenerator()
    : AlgoProcLib()
{

}

int SymmKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    unsigned char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);

    if(param.lenOut > sizeof(buf))
    {
        fprintf(stderr, "%s() len overflow\n", __func__);
        return nret;
    }

    if(RAND_bytes(buf, param.lenOut) > 0)
    {
        param.symmKey = string(reinterpret_cast<const char*>(buf));
        nret = RES_OK;
    }

    printf("%s [symm_key=%s]\n", __func__, param.symmKey.c_str());

    return nret;
}
