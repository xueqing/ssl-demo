#ifndef RSAPRIKEYDECRYPT_H
#define RSAPRIKEYDECRYPT_H

#include "rsacrypt.h"

namespace KMS {

class RSAPrikeyDecrypt : public RSACrypt
{
public:
    RSAPrikeyDecrypt();
    ~RSAPrikeyDecrypt();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // RSAPRIKEYDECRYPT_H
