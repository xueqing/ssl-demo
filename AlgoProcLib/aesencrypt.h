#ifndef AESENCRYPT_H
#define AESENCRYPT_H

#include "algoproclib.h"

namespace KMS {

class AESEncrypt : public AlgoProcLib
{
public:
    AESEncrypt();
    ~AESEncrypt();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // AESENCRYPT_H
