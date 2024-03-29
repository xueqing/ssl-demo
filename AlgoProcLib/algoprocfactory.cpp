#include "algoprocfactory.h"

#include "symmkeygenerator.h"
#include "rsakeygenerator.h"
#include "rsapubkeyencrypt.h"
#include "rsaprikeydecrypt.h"
#include "rsasign.h"
#include "rsaverify.h"
#include "aesencrypt.h"
#include "aesdecrypt.h"
#include "smtwosign.h"
#include "smtwoverify.h"

using namespace KMS;

AlgoProcFactory* AlgoProcFactory::m_pInstance = nullptr;
std::mutex AlgoProcFactory::m_instanceMutex;
AlgoProcFactory::AlgoProcFactoryDestruct AlgoProcFactory::m_destruct;

AlgoProcFactory *AlgoProcFactory::GetInstance()
{
    if(m_pInstance == nullptr)
    {
        std::lock_guard<std::mutex> lock(m_instanceMutex);
        if(m_pInstance == nullptr)
        {
            m_pInstance = new AlgoProcFactory;
        }
    }

    return m_pInstance;
}

AlgoProcLib *AlgoProcFactory::CreateAlgoProc(ALGO_TYPE algotype)
{
    AlgoProcLib *pAlgoProcLib = nullptr;
    switch (algotype) {
    case ALGO_GET_KEY_SYMM:
        pAlgoProcLib = new SymmKeyGenerator;
        break;
    case ALGO_GET_KEY_RSA:
        pAlgoProcLib = new RSAKeyGenerator;
        break;
    case ALGO_RSA_PUB_KEY_ENC:
        pAlgoProcLib = new RSAPubkeyEncrypt;
        break;
    case ALGO_RSA_PRI_KEY_DEC:
        pAlgoProcLib = new RSAPrikeyDecrypt;
        break;
    case ALGO_RSA_SIGN:
        pAlgoProcLib = new RSASign;
        break;
    case ALGO_RSA_VERIFY:
        pAlgoProcLib = new RSAVerify;
        break;
    case ALGO_AES_ENC:
        pAlgoProcLib = new AESEncrypt;
        break;
    case ALGO_AES_DEC:
        pAlgoProcLib = new AESDecrypt;
        break;
    case ALGO_SM2_SIGN:
        pAlgoProcLib = new SMTwoSign;
        break;
    case ALGO_SM2_VERIFY:
        pAlgoProcLib = new SMTwoVerify;
        break;
    default:
        pAlgoProcLib = new AlgoProcLib;
        break;
    }
    return pAlgoProcLib;
}

AlgoProcFactory::AlgoProcFactory()
{

}
