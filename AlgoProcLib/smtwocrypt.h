#ifndef SMTWOCRYPT_H
#define SMTWOCRYPT_H

#include <openssl/ec.h>

#include "algoproclib.h"

namespace KMS {

class SMTwoCrypt : public AlgoProcLib
{
public:
    SMTwoCrypt();
    ~SMTwoCrypt();

    // 从pub文件中获取公钥
    static int LoadPubKey(std::string &filePath, EVP_PKEY **pubKey);
    // 从pem文件中获取私钥
    static int LoadPriKey(std::string &filePath, EVP_PKEY **priKey);

protected:
    // 保存公钥到pub文件中
    int SavePubKey(std::string &filePath, EC_KEY *pKey);
    // 保存私钥到pem文件中
    int SavePriKey(std::string &filePath, EC_KEY *pKey);
};

}//namespace KMS

#endif // SMTWOCRYPT_H
