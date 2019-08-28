#ifndef CSTRING_H
#define CSTRING_H

#include <string>

namespace CString
{
    int StringToNumber(const char *str, uint16_t &num);
    int StringToNumber(const char *str, uint32_t &num);
    int StringToNumber(const char *str, float &num);
    int StringToNumber(const char *str, int &num);
    int StringToNumber(const char *str, long &num);
    int StringToNumber(const char *str, long long &num);

    std::string& ReplaceAll(std::string& str, const std::string& old_value, const std::string& new_value);
}//namespace CString

#endif // CSTRING_H
