#include "algoproclib.h"

#include <string.h>
#include <limits.h>

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "cstring.h"
#include "rsacrypt.h"
#include "mybase64.h"

using namespace KMS;
using namespace std;

string AlgoProcLib::m_strRSAKeyPath;
int AlgoProcLib::m_lenSymmKey = 16;//default 16 bytes

AlgoProcLib::AlgoProcLib()
{
}

AlgoProcLib::~AlgoProcLib()
{
}

bool AlgoProcLib::Initialize(map<string, string> &mapConfParam)
{
    if(mapConfParam.find("rsa_key_path") == mapConfParam.end())
    {
        fprintf(stderr, "%s() failed to initialize rsa_key_path\n", __func__);
        return false;
    }
    m_strRSAKeyPath = mapConfParam.at("rsa_key_path");
    if(m_strRSAKeyPath.back() != '/')
        m_strRSAKeyPath += "/";

    if(mapConfParam.find("symm_key_len") == mapConfParam.end()
        || CString::StringToNumber(mapConfParam.at("symm_key_len").c_str(), m_lenSymmKey) <= 0)
    {
        fprintf(stderr, "%s() failed to initialize symm_key_len\n", __func__);
        return false;
    }

    return true;
}

bool AlgoProcLib::LoadRSAKey()
{
    bool bret = false;

    RSA *pubKey = nullptr;
    RSA *priKey = nullptr;

    do
    {
        if(!(pubKey = RSA_new()) || !(priKey = RSA_new()))
        {
            fprintf(stderr, "%s() failed to new RSA\n", __func__);
            break;
        }

        if(RSACrypt::LoadPubKey(m_strRSAKeyPath, &pubKey) != AlgoProcLib::RES_OK)
            break;

        if(RSACrypt::LoadPriKey(m_strRSAKeyPath, &priKey) != AlgoProcLib::RES_OK)
            break;

        bret = true;
    }while(false);

    RSA_free(pubKey);
    RSA_free(priKey);

    return bret;
}

void AlgoProcLib::Deinitialize()
{

}

int AlgoProcLib::ProcessAlgorithm(AlgorithmParams &/*param*/)
{
    return RES_OK;
}

void AlgoProcLib::ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib)
{
    if(pAlgoProcLib)
        delete pAlgoProcLib;
    pAlgoProcLib = nullptr;
}
