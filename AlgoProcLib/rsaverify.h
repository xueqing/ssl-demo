#ifndef RSAVERIFY_H
#define RSAVERIFY_H

#include "rsacrypt.h"

namespace KMS {

class RSAVerify : public RSACrypt
{
public:
    RSAVerify();
    ~RSAVerify();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // RSAVERIFY_H
