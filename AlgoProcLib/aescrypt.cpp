#include "aescrypt.h"

#include <string.h>
#include <openssl/aes.h>

#include "mybase64.h"

using namespace std;

AESCrypt::AESCrypt()
{

}

AESCrypt::~AESCrypt()
{

}

bool AESCrypt::EncryptByAES(const string &key, const string &inStr, string &outStr)
{
    if(key.empty())
    {
        fprintf(stderr, "%s() AES key is empty\n", __func__);
        return false;
    }

    AES_KEY aes;
    unsigned char *userKey = nullptr;
    int lenKey = -1;
    {
        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        lenKey = Base64Decode(buf64, key.c_str());
        userKey = reinterpret_cast<unsigned char*>(buf64);
    }

    if(AES_set_encrypt_key(userKey, lenKey*8, &aes) < 0)
    {
        fprintf(stderr, "%s() failed to call AES_set_encrypt_key\n", __func__);
        return false;
    }

    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    memset(iv, 0, AES_BLOCK_SIZE);//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

    char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);
    unsigned char *outBuf = reinterpret_cast<unsigned char*>(buf);
    unsigned char *inBuf = reinterpret_cast<unsigned char*>(const_cast<char*>(inStr.c_str()));
    printf("%s() Begin AES_cbc_encrypt ...\n", __func__);
    int inLen = inStr.length();
    AES_cbc_encrypt(inBuf, outBuf, inLen, &aes, iv, AES_ENCRYPT);
    printf("%s() After AES_cbc_encrypt ...\n", __func__);

    char buf64[MAX_BUF_SIZE];
    memset(buf64, 0, MAX_BUF_SIZE);
    int len64 = Base64Encode(buf64, buf, strlen(buf));
    outStr = string(buf64, len64);

    return true;
}

bool AESCrypt::DecryptByAES(const string &key, const string &inStr, string &outStr)
{
    if(key.empty())
    {
        fprintf(stderr, "%s() AES key is empty\n", __func__);
        return false;
    }

    AES_KEY aes;
    unsigned char *userKey = nullptr;
    int lenKey = -1;
    {
        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        lenKey = Base64Decode(buf64, key.c_str());
        userKey = reinterpret_cast<unsigned char*>(buf64);
    }

    if(AES_set_decrypt_key(userKey, lenKey*8, &aes) < 0)
    {
        fprintf(stderr, "%s() failed to call AES_set_decrypt_key\n", __func__);
        return false;
    }

    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    memset(iv, 0, AES_BLOCK_SIZE);//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

    char buf64[MAX_BUF_SIZE];
    memset(buf64, 0, MAX_BUF_SIZE);
    int len64 = Base64Decode(buf64, inStr.c_str());
    if(len64 % AES_BLOCK_SIZE != 0)
    {
        fprintf(stderr, "%s() length of string error\n", __func__);
        return false;
    }

    char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);
    unsigned char *outBuf = reinterpret_cast<unsigned char*>(buf);
    unsigned char *inBuf = reinterpret_cast<unsigned char*>(buf64);
    printf("%s() Begin AES_cbc_decrypt ...\n", __func__);
    AES_cbc_encrypt(inBuf, outBuf, len64, &aes, iv, AES_DECRYPT);
    printf("%s() After AES_cbc_decrypt ...\n", __func__);

    outStr = string(buf, strlen(buf));

    return true;
}
