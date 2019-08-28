#ifndef ALGOPROC_COMMON_H
#define ALGOPROC_COMMON_H

#include <string>

namespace KMS {

enum ALGO_TYPE {
    ALGO_UNKNOWN = 0,
    ALGO_ENC_BASE64,
    ALGO_DEC_BASE64,
    ALGO_GET_KEY_SYMM,
    ALGO_GET_KEY_RSA,
    ALGO_RSA_PUB_KEY_ENC,
    ALGO_RSA_PRI_KEY_DEC,
};

struct AlgorithmParams {
    std::string strIn;
    std::string strOut;
    int lenOut = 0;
    std::string symmKey;
};

}//namespace KMS

#endif // ALGOPROC_COMMON_H
