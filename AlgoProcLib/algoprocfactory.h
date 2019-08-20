#ifndef ALGOPROCFACTORY_H
#define ALGOPROCFACTORY_H

#include <mutex>

#include "algoproclib.h"

namespace KMS {

class AlgoProcFactory
{
public:
    static AlgoProcFactory *GetInstance();

    AlgoProcLib *CreateAlgoProc(KMS::ALGO_TYPE algotype);

private:
    AlgoProcFactory();

    static AlgoProcFactory *m_pInstance;
    static std::mutex m_instanceMutex;

    class AlgoProcFactoryDestruct
    {
    public:
        ~AlgoProcFactoryDestruct()
        {
            if(AlgoProcFactory::m_pInstance)
                delete AlgoProcFactory::m_pInstance;
            AlgoProcFactory::m_pInstance = nullptr;
        }
    };
    static AlgoProcFactoryDestruct m_destruct;
};

}//namespace KMS

#endif // ALGOPROCFACTORY_H
