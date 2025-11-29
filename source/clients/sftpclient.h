#ifndef SFTPCLIENT_H
#define SFTPCLIENT_H

#include <string>
#include <vector>
#include <libssh2.h>
#include <libssh2_sftp.h>

#include "clients/remote_client.h"
#include "common.h"

class SftpClient : public RemoteClient
{
public:
    SftpClient();
    ~SftpClient();

    int Connect(const std::string &url, const std::string &user, const std::string &pass) override;
    int Mkdir(const std::string &path) override;
    int Rmdir(const std::string &path, bool recursive) override;
    int Size(const std::string &path, int64_t *size) override;
    int Get(const std::string &outputfile, const std::string &path, uint64_t offset = 0) override;
    // Download a specific byte range [offset, offset+length) of a remote file into
    // the given local file. The local file must already exist and be large enough.
    int GetSegment(const std::string &outputfile, const std::string &path, uint64_t offset, uint64_t length);
    int GetRange(const std::string &path, void *buffer, uint64_t size, uint64_t offset) override;
    int Put(const std::string &inputfile, const std::string &path, uint64_t offset = 0) override;
    int Rename(const std::string &src, const std::string &dst) override;
    int Delete(const std::string &path) override;
    int Copy(const std::string &from, const std::string &to) override;
    int Move(const std::string &from, const std::string &to) override;
    bool FileExists(const std::string &path) override;
    std::vector<DirEntry> ListDir(const std::string &path) override;
    std::string GetPath(std::string path1, std::string path2) override;
    int GetRange(void *fp, void *buffer, uint64_t size, uint64_t offset) override;
    void *Open(const std::string &path, int flags) override;
    void Close(void *fp) override;
    bool IsConnected() override;
    bool Ping() override;
    const char *LastResponse() override;
    int Quit() override;
    ClientType clientType() override;
    uint32_t SupportedActions() override;

private:
    int sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp;
    bool connected;
    char response[512];
    std::string base_path;

    std::string getFullPath(const std::string &path) const;
    void setResponse(const char *msg);
};

#endif
