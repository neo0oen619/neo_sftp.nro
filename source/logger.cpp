#include "logger.h"

#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <string>

#include "fs.h"
#include "config.h"

namespace
{
    std::string LogPath()
    {
        return std::string(LOG_FILE);
    }

    void EnsureDir()
    {
        FS::MkDirs(std::string(LOG_DIR));
    }
}

void Logger::Init()
{
    if (!logging_enabled)
        return;
    EnsureDir();
}

void Logger::Log(const std::string &msg)
{
    if (!logging_enabled)
        return;
    EnsureDir();
    FILE *fd = FS::Append(LogPath());
    if (!fd)
        return;

    // Timestamp
    std::time_t t = std::time(nullptr);
    std::tm *tm = std::localtime(&t);
    if (tm)
        std::fprintf(fd, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                     tm->tm_hour, tm->tm_min, tm->tm_sec, msg.c_str());
    else
        std::fprintf(fd, "%s\n", msg.c_str());

    std::fclose(fd);
}

void Logger::Logf(const char *fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    Log(std::string(buf));
}
