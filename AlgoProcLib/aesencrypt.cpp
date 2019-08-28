#include "aesencrypt.h"

#include <string.h>

#include <openssl/aes.h>

#include "mybase64.h"

using namespace std;
using namespace KMS;

AESEncrypt::AESEncrypt()
    : AlgoProcLib()
{

}

AESEncrypt::~AESEncrypt()
{
}

int AESEncrypt::ProcessAlgorithm(AlgorithmParams &param)
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

        if(AES_set_encrypt_key(userKey, lenKey*8, &aes) < 0)
        {
            fprintf(stderr, "%s() failed to call AES_set_encrypt_key\n", __func__);
            break;
        }

        unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
        memset(iv, 0, AES_BLOCK_SIZE);//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

        char buf[MAX_BUF_SIZE];
        memset(buf, 0, MAX_BUF_SIZE);
        unsigned char *outBuf = reinterpret_cast<unsigned char*>(buf);
        unsigned char *inBuf = reinterpret_cast<unsigned char*>(const_cast<char*>(param.strIn.c_str()));
        printf("%s() Begin AES_cbc_encrypt ...\n", __func__);
        int inLen = param.strIn.length();
        AES_cbc_encrypt(inBuf, outBuf, inLen, &aes, iv, AES_ENCRYPT);
        printf("%s() After AES_cbc_encrypt ...\n", __func__);

        char buf64[MAX_BUF_SIZE];
        memset(buf64, 0, MAX_BUF_SIZE);
        param.lenOut = Base64Encode(buf64, buf, strlen(buf));
        param.strOut = string(buf64, param.lenOut);

        nret = RES_OK;
    }while(false);

    return nret;
}
