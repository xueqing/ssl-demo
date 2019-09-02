#ifndef RSASIGN_H
#define RSASIGN_H

#include "rsacrypt.h"

namespace KMS {

class RSASign : public RSACrypt
{
public:
    RSASign();
    ~RSASign();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // RSASIGN_H
