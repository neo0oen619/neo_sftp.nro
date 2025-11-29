#pragma once

#include <string>

namespace Logger
{
    void Init();
    void Log(const std::string &msg);
    void Logf(const char *fmt, ...);
}
