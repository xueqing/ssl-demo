#include "algoprocinterface.h"

#include <stdlib.h>

#include "algoprocfactory.h"

using namespace std;
using namespace KMS;

AlgoProcInterface*  AlgoProcInterface::m_pInstance = nullptr;
std::mutex          AlgoProcInterface::m_instanceMutex;
map<ALGO_TYPE, string> AlgoProcInterface::m_algoMap = {
    {ALGO_UNKNOWN, "ALGO_UNKNOWN"},
    {ALGO_ENC_BASE64, "ALGO_ENC_BASE64"},
    {ALGO_DEC_BASE64, "ALGO_DEC_BASE64"},
    {ALGO_GET_KEY_SYMM, "ALGO_GET_KEY_SYMM"},
    {ALGO_GET_KEY_RSA, "ALGO_GET_KEY_RSA"},
    {ALGO_RSA_PUB_KEY_ENC, "ALGO_RSA_PUB_KEY_ENC"},
    {ALGO_RSA_PRI_KEY_DEC, "ALGO_RSA_PRI_KEY_DEC"},
    {ALGO_AES_ENC, "ALGO_AES_ENC"},
    {ALGO_AES_DEC, "ALGO_AES_DEC"},
    {ALGO_SM2_SIGN, "ALGO_SM2_SIGN"},
    {ALGO_SM2_VERIFY, "ALGO_SM2_VERIFY"},
};

AlgoProcInterface::AlgoProcInterfaceDestruct AlgoProcInterface::m_destruct;

AlgoProcInterface *AlgoProcInterface::GetInstance()
{
    if(nullptr == m_pInstance)
    {
        std::unique_lock<std::mutex> locker(m_instanceMutex);
        if(nullptr == m_pInstance)
        {
            m_pInstance = new AlgoProcInterface();
        }
    }
    return m_pInstance;
}

bool AlgoProcInterface::GenerateEncryptedSymmKey(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        // generate random string, base64 encode, get base64 decoded symm key
        AlgorithmParams paramKey;
        if(!dispatchAlgoProcLib(paramKey, ALGO_GET_KEY_SYMM))
            break;

        // RSA pub key encrypt, base64 encode, get rsa encrypted symm key
        AlgorithmParams paramEnc;
        paramEnc.strIn = paramKey.symmKey;
        if(!dispatchAlgoProcLib(paramEnc, ALGO_RSA_PUB_KEY_ENC))
            break;

        param.symmKey = paramKey.symmKey;
        param.strOut = paramEnc.strOut;

        printf("%s [key=%s] [cipher=%s]\n", __func__, param.symmKey.c_str(), param.strOut.c_str());
        bret = true;
    }while(false);
    return bret;
}

bool AlgoProcInterface::DecryptSymmKey(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        // base64 decode, RSA pri key decrypt, get base64 decoded symm key
        AlgorithmParams paramDec;
        paramDec.strIn = param.strIn;
        if(!dispatchAlgoProcLib(paramDec, ALGO_RSA_PRI_KEY_DEC))
            break;

        param.symmKey =  paramDec.strOut;
        param.strOut =  param.strIn;

        printf("%s [key=%s] [cipher=%s]\n", __func__, param.symmKey.c_str(), param.strOut.c_str());
        bret = true;
    }while(false);
    return bret;
}

bool AlgoProcInterface::GenerateRSAKey(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        if(!dispatchAlgoProcLib(param, ALGO_GET_KEY_RSA))
            break;

        bret = true;
    }while(false);
    return bret;
}

bool AlgoProcInterface::EncryptByAES(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        if(!dispatchAlgoProcLib(param, ALGO_AES_ENC))
            break;

        bret = true;
    }while(false);
    return bret;
}

bool AlgoProcInterface::DecryptByAES(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        if(!dispatchAlgoProcLib(param, ALGO_AES_DEC))
            break;

        bret = true;
    }while(false);
    return bret;
}

AlgoProcInterface::AlgoProcInterface()
{

}

bool AlgoProcInterface::dispatchAlgoProcLib(AlgorithmParams &param, ALGO_TYPE algotype)
{
    printf("%s begin [algotype=%s]\n", __func__, m_algoMap.at(algotype).c_str());
    AlgoProcLib *pAlgoProcLib = AlgoProcFactory::GetInstance()->CreateAlgoProc(algotype);
    int nret = pAlgoProcLib->ProcessAlgorithm(param);
    AlgoProcLib::ReleaseAlgoProcLib(pAlgoProcLib);

    printf("%s finish [algotype=%s] [res=%s] [err=%d]\n", __func__, m_algoMap.at(algotype).c_str(),
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), nret);
    return (nret == AlgoProcLib::RES_OK);
}
