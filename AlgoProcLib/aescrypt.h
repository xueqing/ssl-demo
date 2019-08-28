#ifndef AESCRYPT_H
#define AESCRYPT_H

#include <string>

class AESCrypt
{
#define MAX_BUF_SIZE 512
public:
    AESCrypt();
    ~AESCrypt();

    bool EncryptByAES(const std::string &key, const std::string &inStr, std::string &outStr);
    bool DecryptByAES(const std::string &key, const std::string &inStr, std::string &outStr);
};

#endif // AESCRYPT_H
