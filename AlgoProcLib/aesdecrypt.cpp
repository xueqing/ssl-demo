#include "aesdecrypt.h"

#include <string.h>

#include <openssl/aes.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

AESDecrypt::AESDecrypt()
    : AlgoProcLib()
{

}

AESDecrypt::~AESDecrypt()
{
}

int AESDecrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    do
    {
        if(param.aesKey.empty())
        {
            fprintf(stderr, "%s() AES key is empty\n", __func__);
            break;
        }

        AES_KEY aes;
        unsigned char *userKey = nullptr;
        int lenKey = -1;
        {
            char buf64[MAX_BUF_SIZE];
            memset(buf64, 0, MAX_BUF_SIZE);
            lenKey = Base64Decode(buf64, param.aesKey.c_str());
            userKey = reinterpret_cast<unsigned char*>(buf64);
        }

        if(AES_set_decrypt_key(userKey, lenKey*8, &aes) < 0)
        {
            fprintf(stderr, "%s() failed to call AES_set_decrypt_key\n", __func__);
            break;
        }

        unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
        memset(iv, 0, AES_BLOCK_SIZE);//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        int len64 = Base64Decode(buf64, param.strIn.c_str());
        if(len64 % AES_BLOCK_SIZE != 0)
        {
            fprintf(stderr, "%s() length of string error\n", __func__);
            break;
        }

        char buf[MAX_BUF_SIZE];
        memset(buf, 0, MAX_BUF_SIZE);
        unsigned char *outBuf = reinterpret_cast<unsigned char*>(buf);
        unsigned char *inBuf = reinterpret_cast<unsigned char*>(buf64);
        printf("%s() Begin AES_cbc_decrypt ...\n", __func__);
        AES_cbc_encrypt(inBuf, outBuf, len64, &aes, iv, AES_DECRYPT);
        printf("%s() After AES_cbc_decrypt ...\n", __func__);

        param.lenOut = strlen(buf);
        param.strOut = string(buf, param.lenOut);

        nret = RES_OK;
    }while(false);

    return nret;
}
