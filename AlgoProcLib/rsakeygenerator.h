#ifndef RSAKEYGENERATOR_H
#define RSAKEYGENERATOR_H

#include "algoproclib.h"

namespace KMS {

class RSAKeyGenerator : public AlgoProcLib
{
public:
    RSAKeyGenerator();
    ~RSAKeyGenerator();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // RSAKEYGENERATOR_H
