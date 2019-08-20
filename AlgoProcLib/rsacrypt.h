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

protected:
    // 从pem文件中获取公钥
    int LoadPubKey(std::string &filePath);
    // 从pem文件中获取私钥
    int LoadPriKey(std::string &filePath);

    // 释放公钥和私钥结构资源
    int CloseKey();

    // 释放分配的内存资源
    void FreeRes();

    RSA *m_pubKey = nullptr;
    RSA *m_priKey = nullptr;

    unsigned char *m_pubExpd = nullptr;
    unsigned char *m_priExpd = nullptr;
    unsigned char *m_module = nullptr;

    int m_pubExpdLen = -1;
    int m_priExpdLen = -1;
    int m_moduleLen = -1;
};

}//namespace KMS

#endif // RSACRYPT_H
