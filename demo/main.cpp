#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "algoprocinterface.h"
#include "algoproclib.h"

using namespace std;

#define TEST_SYMM_KEY_GENERATOR 0
#define TEST_RSA 0

void TestSymmKeyGenerator();
void TestRSA();

int main()
{
    map<string, string> mapConfParam;
    mapConfParam.emplace(std::make_pair("rsa_key_path", "/home/kiki/qt-workspace/.github/ssl-demo"));
    mapConfParam.emplace(std::make_pair("symm_key_len", "16"));
    KMS::AlgoProcLib::Initialize(mapConfParam);

#if TEST_SYMM_KEY_GENERATOR
    {
        TestSymmKeyGenerator();
    }
#endif

#if TEST_RSA
    {
        TestRSA();
    }
#endif

    KMS::AlgoProcLib::Deinitialize();
    return 0;
}

void TestSymmKeyGenerator()
{
    KMS::AlgorithmParams paramKey;
    paramKey.lenOut = 128 / 8;
    if(!AlgoProcInterface::GetInstance()->GenerateEncryptedSymmKey(paramKey))
    {
        printf("Generate symm key error\n");
        assert(false);
    }
    printf("Generate symm key success [key=%s]\n", paramKey.symmKey.c_str());
}

void TestRSA()
{
    KMS::AlgorithmParams paramRsa;

#define TEST_RSA_KEY_GENERATOR 1
#if TEST_RSA_KEY_GENERATOR
    if(!AlgoProcInterface::GetInstance()->GenerateRSAKey(paramRsa))
    {
        printf("Generate RSA key error\n");
        assert(false);
    }
    printf("Generate RSA key success\n");
#endif

//#define TEST_RSA_PUB_KEY_ENC 1
//#if TEST_RSA_PUB_KEY_ENC
//    KMS::AlgorithmParams paramRsaPub;
//    paramRsaPub.strIn = "IAmStringToBeEncryptedByRSAPubKey";
//    if(!AlgoProcInterface::GetInstance()->GenerateEncryptedSymmKey(paramRsaPub))
//    {
//        printf("RSA pub key encrypt error\n");
//        assert(false);
//    }
//    printf("RSA pub key encrypt success [strOut=%s] [lenOut=%d]\n", paramRsaPub.strOut.c_str(), paramRsaPub.lenOut);
//#endif

//#define TEST_RSA_PRI_KEY_DEC 1
//#if TEST_RSA_PRI_KEY_DEC
//    KMS::AlgorithmParams paramRsaPri;
//    paramRsaPri.strIn =  paramRsaPub.strOut;
//    if(!AlgoProcInterface::GetInstance()->RSAPriKeyDecrypt(paramRsaPri))
//    {
//        printf("RSA pri key decrypt error\n");
//        assert(false);
//    }
//    printf("RSA pri key decrypt success [strOut=%s] [lenOut=%d]\n", paramRsaPri.strOut.c_str(), paramRsaPri.lenOut);
//#endif
}
