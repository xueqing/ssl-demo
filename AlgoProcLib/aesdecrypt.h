#ifndef AESDECRYPT_H
#define AESDECRYPT_H

#include "algoproclib.h"

namespace KMS {

class AESDecrypt : public AlgoProcLib
{
public:
    AESDecrypt();
    ~AESDecrypt();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // AESDECRYPT_H
