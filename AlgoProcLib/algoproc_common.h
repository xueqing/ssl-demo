#ifndef ALGOPROC_COMMON_H
#define ALGOPROC_COMMON_H

#include <string>

namespace KMS {

enum ALGO_TYPE {
    ALGO_UNKNOWN = 0,
    ALGO_ENC_BASE64,
    ALGO_DEC_BASE64,
    ALGO_GET_KEY_SYMM,
};

struct AlgorithmParams {
    std::string uid;
    std::string strIn;
    std::string strOut;
    unsigned int lenOut = 0;
    std::string symmKey;
};

}//namespace KMS

#endif // ALGOPROC_COMMON_H
