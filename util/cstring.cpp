#include "cstring.h"

#include <inttypes.h>

int CString::StringToNumber(const char *str, uint16_t &num)
{
    return sscanf(str, "%" SCNu16, &num);
}

int CString::StringToNumber(const char *str, uint32_t &num)
{
    return sscanf(str, "%" SCNu32, &num);
}

int CString::StringToNumber(const char *str, float &num)
{
    return sscanf(str, "%f", &num);
}

int CString::StringToNumber(const char *str, int &num)
{
    return sscanf(str, "%d", &num);
}

int CString::StringToNumber(const char *str, long &num)
{
    return sscanf(str, "%ld", &num);
}

int CString::StringToNumber(const char *str, long long &num)
{
    return sscanf(str, "%lld", &num);
}

std::string &CString::ReplaceAll(std::string &str, const std::string &old_value, const std::string &new_value)
{
    std::string::size_type pos(0);
    while(true)
    {
        if((pos = str.find(old_value, pos+1)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}
