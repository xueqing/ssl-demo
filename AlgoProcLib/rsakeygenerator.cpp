#include "rsakeygenerator.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;
using namespace KMS;

const int RSA_KEY_LENGTH = 1024;

RSAKeyGenerator::RSAKeyGenerator()
    : AlgoProcLib()
{

}

RSAKeyGenerator::~RSAKeyGenerator()
{
}

int RSAKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
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

        // 用作显示
        RSA_print_fp(stdout, pRsa, 11);

        string pubKeyPath = param.filePath + "_pub.pem";
        if(!(pPubBio = BIO_new_file(pubKeyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file\n", __func__);
            break;
        }
        if(!PEM_write_bio_RSAPublicKey(pPubBio, pRsa))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_RSAPublicKey\n", __func__);
            break;
        }
        printf( "%s() save rsa pub key to %s\n", __func__, pubKeyPath.c_str());

        string priKeyPath = param.filePath + "_pri.pem";
        if(!(pPriBio = BIO_new_file(priKeyPath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to call BIO_new_file\n", __func__);
            break;
        }
        //这里生成的私钥没有加密，可选加密
        if(!PEM_write_bio_RSAPrivateKey(pPriBio, pRsa, nullptr, nullptr, 0, nullptr, nullptr))
        {
            fprintf(stderr, "%s() failed to call PEM_write_bio_RSAPrivateKey\n", __func__);
            break;
        }
        printf( "%s() save rsa pri key to %s\n", __func__, priKeyPath.c_str());

        nret = RES_OK;
    }while(false);

    BN_free(e);
    RSA_free(pRsa);
    BIO_free(pPubBio);
    BIO_free(pPriBio);

    return nret;
}
