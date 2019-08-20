#ifndef RSAPUBKEYENCRYPT_H
#define RSAPUBKEYENCRYPT_H

#include "rsacrypt.h"

namespace KMS {

class RSAPubkeyEncrypt : public RSACrypt
{
public:
    RSAPubkeyEncrypt();
    ~RSAPubkeyEncrypt();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // RSAPUBKEYENCRYPT_H
