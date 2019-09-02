#ifndef SMTWOKEYGENERATOR_H
#define SMTWOKEYGENERATOR_H

#include "smtwocrypt.h"

namespace KMS {

class SMTwoKeyGenerator : public SMTwoCrypt
{
public:
    SMTwoKeyGenerator();
    ~SMTwoKeyGenerator();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &) override;
};

}//namespace KMS

#endif // SMTWOKEYGENERATOR_H
