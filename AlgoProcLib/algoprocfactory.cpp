#include "algoprocfactory.h"

#include "symmkeygenerator.h"

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
    default:
        pAlgoProcLib = new AlgoProcLib(algotype);
        break;
    }
    return pAlgoProcLib;
}

AlgoProcFactory::AlgoProcFactory()
{

}
