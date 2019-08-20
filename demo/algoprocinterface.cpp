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
};

AlgoProcInterface::AlgoProcInterfaceDestruct AlgoProcInterface::m_destruct;

const string SKS_DATA_PATH = "/tmp/sks";

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

bool AlgoProcInterface::GenerateSymmKey(AlgorithmParams &param)
{
    bool bret = false;
    do
    {
        // SM4 key: 128 bit
        param.lenOut = 128/8;
        if(!dispatchAlgoProcLib(param, ALGO_GET_KEY_SYMM))
            break;

        AlgorithmParams param64;
        param64.strIn = param.symmKey;
        if(!dispatchAlgoProcLib(param64, ALGO_ENC_BASE64))
            break;

        param.symmKey = param64.strOut;
        bret = true;
    }while(false);
    return bret;
}

bool AlgoProcInterface::Base64Encode(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_ENC_BASE64);
}

bool AlgoProcInterface::Base64Decode(AlgorithmParams &param)
{
   return dispatchAlgoProcLib(param, ALGO_DEC_BASE64);
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
