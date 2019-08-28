#ifndef RSAKEYGENERATOR_H
#define RSAKEYGENERATOR_H

#include "rsacrypt.h"

namespace KMS {

class RSAKeyGenerator : public RSACrypt
{
public:
    RSAKeyGenerator();
    ~RSAKeyGenerator();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &) override;
};

}//namespace KMS

#endif // RSAKEYGENERATOR_H
