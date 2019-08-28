#ifndef ALGOPROCINTERFACE_H
#define ALGOPROCINTERFACE_H

#include <mutex>
#include <map>

#include "algoproc_common.h"

class AlgoProcInterface
{
public:
    static AlgoProcInterface* GetInstance();

    bool GenerateEncryptedSymmKey(KMS::AlgorithmParams &param);
    bool DecryptSymmKey(KMS::AlgorithmParams &param);

    bool GenerateRSAKey(KMS::AlgorithmParams &param);

private:
    AlgoProcInterface();
    static AlgoProcInterface* m_pInstance;
    static std::mutex         m_instanceMutex;

    static std::map<KMS::ALGO_TYPE, std::string> m_algoMap;

    bool dispatchAlgoProcLib(KMS::AlgorithmParams &param, KMS::ALGO_TYPE algotype);

    class AlgoProcInterfaceDestruct
    {
    public:
        ~AlgoProcInterfaceDestruct()
        {
            if(AlgoProcInterface::m_pInstance)
                delete AlgoProcInterface::m_pInstance;
            AlgoProcInterface::m_pInstance = nullptr;
        }
    };
    static AlgoProcInterfaceDestruct m_destruct;
};


#endif // ALGOPROCINTERFACE_H
