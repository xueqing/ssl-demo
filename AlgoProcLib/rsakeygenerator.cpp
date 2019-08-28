#include "rsakeygenerator.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;
using namespace KMS;

const int RSA_KEY_LENGTH = 1024;

RSAKeyGenerator::RSAKeyGenerator()
    : RSACrypt()
{

}

RSAKeyGenerator::~RSAKeyGenerator()
{
}

int RSAKeyGenerator::ProcessAlgorithm(AlgorithmParams &/*param*/)
{
    int nret = RES_SERVER_ERROR;

    BIGNUM *e = nullptr;
    RSA *pRsa = nullptr;
    BIO *pPubBio = nullptr;
    BIO *pPriBio = nullptr;

    do
    {
        e = BN_new();
        BN_set_word(e, 65537);

        if(!(pRsa = RSA_new())
                || !(RSA_generate_key_ex(pRsa, RSA_KEY_LENGTH, e, nullptr)))
        {
            fprintf(stderr, "%s() failed to generate RSA\n", __func__);
            break;
        }

        if(SavePubKey(m_strRSAKeyPath, pRsa) != AlgoProcLib::RES_OK)
            break;

        if(SavePriKey(m_strRSAKeyPath, pRsa) != AlgoProcLib::RES_OK)
            break;

        nret = RES_OK;
    }while(false);

    BN_free(e);
    RSA_free(pRsa);
    BIO_free(pPubBio);
    BIO_free(pPriBio);

    return nret;
}
