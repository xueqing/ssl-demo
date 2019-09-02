#include "smtwokeygenerator.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;
using namespace KMS;

const int SM2_KEY_LENGTH = 1024;

SMTwoKeyGenerator::SMTwoKeyGenerator()
    : SMTwoCrypt()
{

}

SMTwoKeyGenerator::~SMTwoKeyGenerator()
{
}

int SMTwoKeyGenerator::ProcessAlgorithm(AlgorithmParams &/*param*/)
{
    int nret = RES_SERVER_ERROR;

    EC_KEY *ecKey=nullptr;

    do
    {
        /*
         * SM2标准文本中提供了四个测试用椭圆曲线域参数:
         *  192比特素数域椭圆曲线域参数（sm2p192test)
         *  256比特素数域椭圆曲线域参数（sm2p256test)
         *  193比特二进制域椭圆曲线域参数 (sm2b193test)
         *  257比特二进制域椭圆曲线域参数 (sm2b257test)
         */
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        // For cert signing, if not, will result in a SSL error of 0x1408a0c1 (no shared cipher)
        EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

        if(EC_KEY_generate_key(ecKey) != 1)
        {
            fprintf(stderr, "%s() failed to call EC_KEY_generate_key\n", __func__);
            break;
        }

        if(SavePubKey(m_strSM2KeyPath, ecKey) != AlgoProcLib::RES_OK)
            break;

        if(SavePriKey(m_strSM2KeyPath, ecKey) != AlgoProcLib::RES_OK)
            break;

        nret = RES_OK;
    }while(false);

    EC_KEY_free(ecKey);

    return nret;
}
