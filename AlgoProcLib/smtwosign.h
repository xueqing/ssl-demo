#ifndef SMTWOSIGN_H
#define SMTWOSIGN_H

#include "smtwocrypt.h"

namespace KMS {

class SMTwoSign : public SMTwoCrypt
{
public:
    SMTwoSign();
    ~SMTwoSign();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // SMTWOSIGN_H
