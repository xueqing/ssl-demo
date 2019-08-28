#ifndef RSACRYPT_H
#define RSACRYPT_H

#include <openssl/rsa.h>

#include "algoproclib.h"

namespace KMS {

class RSACrypt : public AlgoProcLib
{
public:
    RSACrypt();
    ~RSACrypt();

    // 从pem文件中获取公钥
    static int LoadPubKey(std::string &filePath, RSA **pubKey);
    // 从pem文件中获取私钥
    static int LoadPriKey(std::string &filePath, RSA **priKey);

protected:
    // 保存公钥到pem文件中
    int SavePubKey(std::string &filePath, RSA *pRsa);
    // 保存私钥到pem文件中
    int SavePriKey(std::string &filePath, RSA *pRsa);
};

}//namespace KMS

#endif // RSACRYPT_H
