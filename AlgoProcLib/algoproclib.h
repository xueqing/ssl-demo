#ifndef ALGOPROCLIB_H
#define ALGOPROCLIB_H

#include <map>

#include "algoproc_common.h"

namespace KMS {

class AlgoProcLib
{
#define MAX_BUF_SIZE 512
public:
    enum PROC_RES
    {
        RES_OK = 0,
        RES_NOT_SUPPORTED,
        RES_SERVER_ERROR,
        RES_VERIFY_FAILURE,
    };

    AlgoProcLib();
    virtual ~AlgoProcLib();

    static bool Initialize(std::map<std::string, std::string> &mapConfParam); // must be called before using it
    static bool LoadRSAKey();
    static void Deinitialize(); // must be called after using it

    virtual int ProcessAlgorithm(AlgorithmParams &); //ref PROC_RES
    static void ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib);

protected:
    static std::string m_strRSAKeyPath;
    static int m_lenSymmKey;
};

}//namespace KMS

#endif // ALGOPROCLIB_H
