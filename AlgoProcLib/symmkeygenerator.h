#ifndef SYMMKEYGENERATOR_H
#define SYMMKEYGENERATOR_H

#include "algoproclib.h"

namespace KMS {

class SymmKeyGenerator : public AlgoProcLib
{
public:
    SymmKeyGenerator();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // SYMMKEYGENERATOR_H
