#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "algoprocinterface.h"
#include "algoproclib.h"

using namespace std;

#define TEST_SYMM_KEY_GENERATOR 0
#define TEST_RSA 0
#define TEST_AES 0
#define TEST_RSA_SIGN_VERIYF 1

void TestSymmKeyGenerator();
void TestRSA();
void TestAES();
void TestRSASignVerify();

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

#if TEST_RSA_SIGN_VERIYF
    {
        TestRSASignVerify();
    }
#endif

#if TEST_AES
    {
        TestAES();
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

void TestAES()
{
    KMS::AlgorithmParams paramKey;
    paramKey.lenOut = 128 / 8;
    if(!AlgoProcInterface::GetInstance()->GenerateEncryptedSymmKey(paramKey))
    {
        printf("Generate symm key error\n");
        assert(false);
    }
    printf("Generate symm key success [key=%s]\n", paramKey.symmKey.c_str());

#define TEST_AES_ENC_DEC 1
#if TEST_AES_ENC_DEC
    KMS::AlgorithmParams paramAesEnc;
    paramAesEnc.aesKey = paramKey.symmKey;
    paramAesEnc.strIn = "IAmStringToBeEncryptedByAES";//123456789 123456789 123456789 12a;;;;IAmStringToBeEncryptedByAES
    if(!AlgoProcInterface::GetInstance()->EncryptByAES(paramAesEnc))
    {
        printf("AES encrypt error\n");
        assert(false);
    }
    printf("AES encrypt success [strOut=%s] [lenOut=%d]\n", paramAesEnc.strOut.c_str(), paramAesEnc.lenOut);

    KMS::AlgorithmParams paramAesDec;
    paramAesDec.aesKey = paramKey.symmKey;
    paramAesDec.strIn =  paramAesEnc.strOut;
    if(!AlgoProcInterface::GetInstance()->DecryptByAES(paramAesDec))
    {
        printf("AES decrypt error\n");
        assert(false);
    }
    printf("AES decrypt success [strOut=%s] [lenOut=%d]\n", paramAesDec.strOut.c_str(), paramAesDec.lenOut);

    if(paramAesEnc.strIn != paramAesDec.strOut)
    {
        printf("AES test error\n");
        assert(false);
    }
#endif
}

void TestRSASignVerify()
{
    KMS::AlgorithmParams paramRSASign;
    paramRSASign.strIn = "IAmStringToBeSignedByRSA";
    if(!AlgoProcInterface::GetInstance()->SignByRSA(paramRSASign))
    {
        printf("RSA sign error\n");
        assert(false);
    }
    printf("RSA sign success [strOut=%s] [lenOut=%d]\n", paramRSASign.strOut.c_str(), paramRSASign.lenOut);

    if(!AlgoProcInterface::GetInstance()->VerifyByRSA(paramRSASign))
    {
        printf("RSA verify error\n");
        assert(false);
    }
    printf("RSA verify success [strIn=%s] [strOut=%s]\n", paramRSASign.strIn.c_str(), paramRSASign.strOut.c_str());
}
