#ifndef MYBASE64_H
#define MYBASE64_H

#ifdef __cplusplus
extern "C" {
#endif

    int Base64EncodeLen(int len);
    int Base64Encode(char* coded_dst, const char* plain_src, int len_plain_src);

    int Base64Decode_len(const char* coded_src);
    int Base64Decode(char* plain_dst, const char* coded_src);

#ifdef __cplusplus
}
#endif

#endif //MYBASE64_H
