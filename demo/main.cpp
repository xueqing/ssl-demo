#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "algoprocinterface.h"
#include "algoproclib.h"

using namespace std;

#define TEST_BASE64 1
#define TEST_SYMM_KEY_GENERATOR 1
#define TEST_RSA 1

void TestBase64();
void TestBase64Encode(KMS::AlgorithmParams &param);
void TestBase64Decode(KMS::AlgorithmParams &param);
void TestSymmKeyGenerator();
void TestRSA();

int main()
{
//    KMS::AlgoProcLib::Initialize();
#if TEST_BASE64
    {
        TestBase64();
    }
#endif

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

//    KMS::AlgoProcLib::Deinitialize();
    return 0;
}

void TestBase64()
{
    KMS::AlgorithmParams param;
    param.lenOut = 128 / 8;
    if(!AlgoProcInterface::GetInstance()->GenerateSymmKey(param))
    {
        printf("Generate symm key error\n");
        assert(false);
    }
    printf("Generate symm key success [key=%s]\n", param.symmKey.c_str());

    KMS::AlgorithmParams paramEn;
    paramEn.strIn = param.symmKey;
    paramEn.lenOut = 128;
    TestBase64Encode(paramEn);
    printf("Base64 test [base64_encode_str=%s]\n", paramEn.strOut.c_str());

    KMS::AlgorithmParams paramDe;
    paramDe.strIn = paramEn.strOut;
    paramDe.lenOut = 128;
    TestBase64Decode(paramDe);

    if(paramEn.strIn == paramDe.strOut)
        printf("Base64 test success\n");
    else
    {
        printf("Base64 test failure\n");
        assert(false);
    }
}

void TestBase64Encode(KMS::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Encode(param))
    {
        printf("Base64 encode error\n");
        assert(false);
    }
    printf("Base64 encode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestBase64Decode(KMS::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Decode(param))
    {
        printf("Base64 decode error\n");
        assert(false);
    }
    printf("Base64 decode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestSymmKeyGenerator()
{
    KMS::AlgorithmParams paramKey;
    paramKey.lenOut = 128 / 8;
    if(!AlgoProcInterface::GetInstance()->GenerateSymmKey(paramKey))
    {
        printf("Generate symm key error\n");
        assert(false);
    }
    printf("Generate symm key success [key=%s]\n", paramKey.symmKey.c_str());
}

void TestRSA()
{
#define TEST_RSA_KEY_GENERATOR 0
#if TEST_RSA_KEY_GENERATOR
    KMS::AlgorithmParams paramRsa;
    paramRsa.filePath = "/home/kiki/github/ssl-demo/rsa_keys";
    if(!AlgoProcInterface::GetInstance()->GenerateRSAKey(paramRsa))
    {
        printf("Generate RSA key error\n");
        assert(false);
    }
    printf("Generate RSA key success\n");
#endif
}
