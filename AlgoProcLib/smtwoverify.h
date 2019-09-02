#ifndef SMTWOVERIFY_H
#define SMTWOVERIFY_H

#include "smtwocrypt.h"

namespace KMS {

class SMTwoVerify : public SMTwoCrypt
{
public:
    SMTwoVerify();
    ~SMTwoVerify();

    // 生成密钥函数
    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace KMS

#endif // SMTWOVERIFY_H
