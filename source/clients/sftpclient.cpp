#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "lang.h"
#include "util.h"
#include "config.h"
#include "clients/sftpclient.h"

// Progress and cancel globals defined in windows.cpp
extern int64_t bytes_transfered;
extern bool stop_activity;

static bool g_libssh2_initialized = false;
// Tunable constants for throughput.
// Use smaller buffers so progress updates feel smoother and avoid large "burst"
// writes. Tuned for more stable throughput display on Switch.
static const size_t kTransferBufferSize = 512 * 1024; // 512 KB transfer buffer
static const int kSocketBufferSize = 512 * 1024;      // 512 KB TCP buffers

// Simple DNS helpers to fall back to public resolvers when system DNS fails.
static bool SkipDnsName(const unsigned char *buf, size_t len, size_t &offset)
{
    while (offset < len)
    {
        unsigned char labellen = buf[offset];
        if (labellen == 0)
        {
            offset += 1;
            return true;
        }
        // Compression pointer: 11xxxxxx xxxxxxxx
        if ((labellen & 0xC0) == 0xC0)
        {
            if (offset + 1 >= len)
                return false;
            offset += 2;
            return true;
        }
        offset += 1 + labellen;
    }
    return false;
}

static bool ResolveHostWithServer(const std::string &host, int port, const char *dns_ip, struct sockaddr_in *out_addr)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return false;

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, dns_ip, &dns_addr.sin_addr) != 1)
    {
        close(sockfd);
        return false;
    }

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));

    uint16_t id = (uint16_t)rand();
    buf[0] = (id >> 8) & 0xFF;
    buf[1] = id & 0xFF;
    buf[2] = 0x01; // RD
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT = 1
    // ANCOUNT, NSCOUNT, ARCOUNT already zero

    size_t offset = 12;
    std::string h = host;
    // ensure no trailing dot
    if (!h.empty() && h.back() == '.')
        h.pop_back();

    size_t start = 0;
    while (start < h.size() && offset + 1 < sizeof(buf))
    {
        size_t dot = h.find('.', start);
        if (dot == std::string::npos)
            dot = h.size();
        size_t labellen = dot - start;
        if (labellen > 63 || offset + 1 + labellen >= sizeof(buf))
        {
            close(sockfd);
            return false;
        }
        buf[offset++] = (unsigned char)labellen;
        memcpy(buf + offset, h.c_str() + start, labellen);
        offset += labellen;
        start = dot;
        if (start < h.size() && h[start] == '.')
            start++;
    }
    if (offset >= sizeof(buf))
    {
        close(sockfd);
        return false;
    }
    buf[offset++] = 0; // end of qname

    // QTYPE=A, QCLASS=IN
    if (offset + 4 > sizeof(buf))
    {
        close(sockfd);
        return false;
    }
    buf[offset++] = 0;
    buf[offset++] = 1;
    buf[offset++] = 0;
    buf[offset++] = 1;

    ssize_t sent = sendto(sockfd, buf, offset, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr));
    if (sent < 0)
    {
        close(sockfd);
        return false;
    }

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t recvd = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&from_addr, &from_len);
    if (recvd <= 0)
    {
        close(sockfd);
        return false;
    }
    close(sockfd);

    if (recvd < 12)
        return false;

    size_t resp_len = (size_t)recvd;
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    uint16_t ancount = (buf[6] << 8) | buf[7];
    uint16_t nscount = (buf[8] << 8) | buf[9];
    uint16_t arcount = (buf[10] << 8) | buf[11];
    if (qdcount != 1 || (ancount + arcount) == 0)
        return false;

    size_t resp_off = 12;
    if (!SkipDnsName(buf, resp_len, resp_off))
        return false;
    if (resp_off + 4 > resp_len)
        return false;
    // skip QTYPE/QCLASS
    resp_off += 4;

    uint32_t total_rr = (uint32_t)ancount + (uint32_t)nscount + (uint32_t)arcount;

    for (uint32_t i = 0; i < total_rr && resp_off + 12 <= resp_len; ++i)
    {
        if (!SkipDnsName(buf, resp_len, resp_off))
            return false;
        if (resp_off + 10 > resp_len)
            return false;
        uint16_t type = (buf[resp_off] << 8) | buf[resp_off + 1];
        uint16_t clas = (buf[resp_off + 2] << 8) | buf[resp_off + 3];
        uint16_t rdlength = (buf[resp_off + 8] << 8) | buf[resp_off + 9];
        resp_off += 10;
        if (resp_off + rdlength > resp_len)
            return false;

        if (type == 1 && clas == 1 && rdlength == 4)
        {
            memset(out_addr, 0, sizeof(*out_addr));
            out_addr->sin_family = AF_INET;
            out_addr->sin_port = htons(port);
            memcpy(&out_addr->sin_addr, buf + resp_off, 4);
            return true;
        }
        resp_off += rdlength;
    }

    return false;
}

static bool ResolveHostFallback(const std::string &host, int port, struct sockaddr_in *out_addr)
{
    const char *dns_servers[] = {"1.1.1.1", "8.8.8.8"};

    for (const char *dns_ip : dns_servers)
    {
        if (ResolveHostWithServer(host, port, dns_ip, out_addr))
            return true;
    }
    return false;
}

SftpClient::SftpClient()
{
    sock = -1;
    session = nullptr;
    sftp = nullptr;
    connected = false;
    memset(response, 0, sizeof(response));

    if (!g_libssh2_initialized)
    {
        if (libssh2_init(0) == 0)
            g_libssh2_initialized = true;
    }
}

SftpClient::~SftpClient()
{
    Quit();
}

void SftpClient::setResponse(const char *msg)
{
    if (!msg)
    {
        response[0] = '\0';
        return;
    }
    snprintf(response, sizeof(response), "%s", msg);
}

std::string SftpClient::getFullPath(const std::string &ppath) const
{
    std::string path = ppath;
    path = Util::Trim(path, " ");
    path = Util::Trim(path, "/");

    std::string full = base_path;
    if (!full.empty())
    {
        if (!path.empty())
            full = full + "/" + path;
    }
    else
    {
        full = path;
    }

    if (full.empty())
        full = "/";
    else
        full = "/" + full;

    Util::ReplaceAll(full, "//", "/");
    return full;
}

int SftpClient::Connect(const std::string &url, const std::string &user, const std::string &pass)
{
    if (!g_libssh2_initialized)
    {
        setResponse("libssh2_init failed");
        return 0;
    }

    if (connected)
        Quit();

    // Parse URL: sftp://host[:port][/base]
    std::string host_part;
    std::string path_part;
    int port = 22;

    const std::string prefix = "sftp://";
    if (url.compare(0, prefix.size(), prefix) != 0)
    {
        setResponse(lang_strings[STR_PROTOCOL_NOT_SUPPORTED]);
        return 0;
    }

    std::string remainder = url.substr(prefix.size());
    size_t slash_pos = remainder.find('/');
    if (slash_pos != std::string::npos)
    {
        host_part = remainder.substr(0, slash_pos);
        path_part = remainder.substr(slash_pos);
    }
    else
    {
        host_part = remainder;
        path_part.clear();
    }

    size_t colon_pos = host_part.find(':');
    if (colon_pos != std::string::npos)
    {
        port = std::atoi(host_part.substr(colon_pos + 1).c_str());
        host_part = host_part.substr(0, colon_pos);
    }

    if (host_part.empty())
    {
        setResponse(lang_strings[STR_COULD_NOT_RESOLVE_HOST]);
        return 0;
    }

    base_path = path_part;
    base_path = Util::Trim(base_path, " ");
    base_path = Util::Trim(base_path, "/");

    // Resolve host: try numeric IPv4/IPv6 first, then system DNS (IPv4/IPv6),
    // then fallback IPv4 DNS.
    struct sockaddr_storage server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    socklen_t server_addr_len = 0;
    bool resolved = false;

    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, host_part.c_str(), &v4) == 1)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)&server_addr;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = v4;
        server_addr_len = sizeof(struct sockaddr_in);
        resolved = true;
    }
    else if (inet_pton(AF_INET6, host_part.c_str(), &v6) == 1)
    {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server_addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        sa6->sin6_addr = v6;
        server_addr_len = sizeof(struct sockaddr_in6);
        resolved = true;
    }
    else
    {
        // First try getaddrinfo with AF_UNSPEC (IPv4 or IPv6).
        struct addrinfo hints;
        struct addrinfo *res = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);

        int gai = getaddrinfo(host_part.c_str(), port_str, &hints, &res);
        int last_gai = gai;
        if (gai == 0 && res)
        {
            // Prefer IPv4 results first, then IPv6.
            struct addrinfo *chosen = nullptr;
            for (struct addrinfo *p = res; p != nullptr; p = p->ai_next)
            {
                if (p->ai_family == AF_INET)
                {
                    chosen = p;
                    break;
                }
            }
            if (!chosen)
            {
                for (struct addrinfo *p = res; p != nullptr; p = p->ai_next)
                {
                    if (p->ai_family == AF_INET6)
                    {
                        chosen = p;
                        break;
                    }
                }
            }

            if (chosen)
            {
                size_t copy_len = chosen->ai_addrlen;
                if (copy_len > sizeof(server_addr))
                    copy_len = sizeof(server_addr);
                memcpy(&server_addr, chosen->ai_addr, copy_len);
                server_addr_len = (socklen_t)copy_len;
                resolved = true;
            }
            freeaddrinfo(res);
        }
        else
        {
            if (res)
                freeaddrinfo(res);
        }

        // If getaddrinfo failed or returned nothing usable, fall back to gethostbyname (IPv4).
        if (!resolved)
        {
            struct hostent *he = gethostbyname(host_part.c_str());
            if (he && he->h_addrtype == AF_INET && he->h_addr_list && he->h_addr_list[0])
            {
                struct in_addr addr_in;
                memcpy(&addr_in, he->h_addr_list[0], sizeof(struct in_addr));

                struct sockaddr_in v4_he;
                memset(&v4_he, 0, sizeof(v4_he));
                v4_he.sin_family = AF_INET;
                v4_he.sin_port = htons(port);
                v4_he.sin_addr = addr_in;

                memcpy(&server_addr, &v4_he, sizeof(v4_he));
                server_addr_len = sizeof(struct sockaddr_in);
                resolved = true;
            }
        }

        // If still not resolved, try manual IPv4 DNS against known public resolvers.
        if (!resolved)
        {
            struct sockaddr_in v4_addr;
            memset(&v4_addr, 0, sizeof(v4_addr));
            v4_addr.sin_family = AF_INET;
            v4_addr.sin_port = htons(port);
            if (!ResolveHostFallback(host_part, port, &v4_addr))
            {
                char buf[256];
                if (last_gai != 0)
                {
                    snprintf(buf, sizeof(buf), "%s (%s)",
                             lang_strings[STR_COULD_NOT_RESOLVE_HOST],
                             gai_strerror(last_gai));
                }
                else
                {
                    snprintf(buf, sizeof(buf), "%s (fallback DNS failed)",
                             lang_strings[STR_COULD_NOT_RESOLVE_HOST]);
                }
                setResponse(buf);
                return 0;
            }
            memcpy(&server_addr, &v4_addr, sizeof(v4_addr));
            server_addr_len = sizeof(struct sockaddr_in);
            resolved = true;
        }
    }

    int s = socket(((struct sockaddr *)&server_addr)->sa_family, SOCK_STREAM, 0);
    if (s < 0)
    {
        setResponse(lang_strings[STR_FAIL_TIMEOUT_MSG]);
        return 0;
    }

    int bufsize = kSocketBufferSize;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    if (connect(s, (struct sockaddr *)&server_addr, server_addr_len) != 0)
    {
        close(s);
        setResponse(lang_strings[STR_FAIL_TIMEOUT_MSG]);
        return 0;
    }

    LIBSSH2_SESSION *sess = libssh2_session_init();
    if (!sess)
    {
        close(s);
        setResponse("Failed to create SSH session");
        return 0;
    }

    libssh2_session_set_blocking(sess, 1);

    // Prefer faster modern ciphers/MACs and disable expensive compression by default.
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_KEX,
                                "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,"
                                "diffie-hellman-group14-sha1");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_CRYPT_CS,
                                "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_CRYPT_SC,
                                "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_MAC_CS,
                                "hmac-sha2-256,hmac-sha1");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_MAC_SC,
                                "hmac-sha2-256,hmac-sha1");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_COMP_CS, "none,zlib@openssh.com,zlib");
    libssh2_session_method_pref(sess, LIBSSH2_METHOD_COMP_SC, "none,zlib@openssh.com,zlib");

    int rc = libssh2_session_handshake(sess, s);
    if (rc != 0)
    {
        char *errmsg = nullptr;
        int errcode = libssh2_session_last_error(sess, &errmsg, nullptr, 0);
        char buf[256];
        snprintf(buf, sizeof(buf), "SSH handshake failed (%d): %s", errcode, errmsg ? errmsg : "");
        setResponse(buf);
        libssh2_session_free(sess);
        close(s);
        return 0;
    }

    rc = libssh2_userauth_password(sess, user.c_str(), pass.c_str());
    if (rc != 0)
    {
        char *errmsg = nullptr;
        int errcode = libssh2_session_last_error(sess, &errmsg, nullptr, 0);
        char buf[256];
        snprintf(buf, sizeof(buf), "%s (%d): %s", lang_strings[STR_FAIL_LOGIN_MSG], errcode, errmsg ? errmsg : "");
        setResponse(buf);
        libssh2_session_disconnect(sess, "Authentication failed");
        libssh2_session_free(sess);
        close(s);
        return 0;
    }

    LIBSSH2_SFTP *sftp_sess = libssh2_sftp_init(sess);
    if (!sftp_sess)
    {
        char *errmsg = nullptr;
        int errcode = libssh2_session_last_error(sess, &errmsg, nullptr, 0);
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to initialize SFTP (%d): %s", errcode, errmsg ? errmsg : "");
        setResponse(buf);
        libssh2_session_disconnect(sess, "SFTP init failed");
        libssh2_session_free(sess);
        close(s);
        return 0;
    }

    sock = s;
    session = sess;
    sftp = sftp_sess;
    connected = true;

    setResponse(lang_strings[STR_CONNECT]);
    return 1;
}

int SftpClient::Mkdir(const std::string &path)
{
    if (!connected || !sftp)
        return 0;

    std::string full = getFullPath(path);
    int rc = libssh2_sftp_mkdir_ex(sftp, full.c_str(), (unsigned int)full.size(),
                                   LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR |
                                   LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH);
    if (rc == 0)
        return 1;

    setResponse(lang_strings[STR_UNSUPPORTED_OPERATION_MSG]);
    return 0;
}

int SftpClient::Rmdir(const std::string &path, bool recursive)
{
    if (!connected || !sftp)
        return 0;

    std::string full = getFullPath(path);
    int rc = libssh2_sftp_rmdir_ex(sftp, full.c_str(), (unsigned int)full.size());
    if (rc == 0)
        return 1;

    setResponse(lang_strings[STR_UNSUPPORTED_OPERATION_MSG]);
    return 0;
}

int SftpClient::Size(const std::string &path, int64_t *size)
{
    if (!connected || !sftp || !size)
        return 0;

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int rc = libssh2_sftp_stat_ex(sftp, full.c_str(), (unsigned int)full.size(),
                                  LIBSSH2_SFTP_STAT, &attrs);
    if (rc != 0)
        return 0;

    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE)
    {
        *size = (int64_t)attrs.filesize;
        return 1;
    }
    return 0;
}

int SftpClient::Get(const std::string &outputfile, const std::string &path, uint64_t offset)
{
    if (!connected || !sftp)
        return 0;

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open_ex(
        sftp, full.c_str(), (unsigned int)full.size(),
        LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
    if (!handle)
    {
        setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        return 0;
    }

    FILE *file = fopen(outputfile.c_str(), "wb");
    if (!file)
    {
        libssh2_sftp_close(handle);
        setResponse(lang_strings[STR_FAIL_CREATE_LOCAL_FILE_MSG]);
        return 0;
    }

    // Use a fully buffered FILE* with a buffer similar to our transfer buffer.
    // This reduces syscall overhead when writing many large chunks.
    setvbuf(file, nullptr, _IOFBF, kTransferBufferSize);

    if (offset > 0)
    {
        libssh2_sftp_seek64(handle, offset);
        fseeko(file, (off_t)offset, SEEK_SET);
    }

    std::vector<char> buffer(kTransferBufferSize);

    while (true)
    {
        if (stop_activity)
        {
            setResponse(lang_strings[STR_CANCEL_ACTION_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            // Leave partial file on disk so the user can see it.
            return 0;
        }

        ssize_t rc = libssh2_sftp_read(handle, buffer.data(), buffer.size());
        if (rc < 0)
        {
            setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }
        if (rc == 0)
            break;

        size_t written = fwrite(buffer.data(), 1, (size_t)rc, file);
        if (written != (size_t)rc)
        {
            setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }

        // Update global progress counter used by the GUI.
        bytes_transfered += (int64_t)rc;
    }

    fclose(file);
    libssh2_sftp_close(handle);
    setResponse(lang_strings[STR_DOWNLOADING]);
    return 1;
}

int SftpClient::GetSegment(const std::string &outputfile, const std::string &path, uint64_t offset, uint64_t length)
{
    if (!connected || !sftp || length == 0)
        return 0;

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open_ex(
        sftp, full.c_str(), (unsigned int)full.size(),
        LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
    if (!handle)
    {
        setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        return 0;
    }

    FILE *file = fopen(outputfile.c_str(), "r+b");
    if (!file)
    {
        libssh2_sftp_close(handle);
        setResponse(lang_strings[STR_FAIL_CREATE_LOCAL_FILE_MSG]);
        return 0;
    }

    setvbuf(file, nullptr, _IOFBF, kTransferBufferSize);

    libssh2_sftp_seek64(handle, offset);
    fseeko(file, (off_t)offset, SEEK_SET);

    std::vector<char> buffer(kTransferBufferSize);
    uint64_t remaining = length;

    while (remaining > 0)
    {
        if (stop_activity)
        {
            setResponse(lang_strings[STR_CANCEL_ACTION_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }

        size_t to_read = buffer.size();
        if (remaining < to_read)
            to_read = (size_t)remaining;

        ssize_t rc = libssh2_sftp_read(handle, buffer.data(), to_read);
        if (rc < 0)
        {
            setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }
        if (rc == 0)
            break;

        size_t written = fwrite(buffer.data(), 1, (size_t)rc, file);
        if (written != (size_t)rc)
        {
            setResponse(lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }

        remaining -= (uint64_t)rc;
        bytes_transfered += (int64_t)rc;
    }

    fclose(file);
    libssh2_sftp_close(handle);
    return remaining == 0 ? 1 : 0;
}

int SftpClient::GetRange(const std::string &path, void *buffer, uint64_t size, uint64_t offset)
{
    if (!connected || !sftp || !buffer || size == 0)
        return 0;

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open_ex(
        sftp, full.c_str(), (unsigned int)full.size(),
        LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
    if (!handle)
        return 0;

    libssh2_sftp_seek64(handle, offset);

    uint64_t remaining = size;
    char *out = static_cast<char *>(buffer);

    while (remaining > 0)
    {
        ssize_t rc = libssh2_sftp_read(handle, out, (size_t)remaining);
        if (rc <= 0)
            break;
        remaining -= (uint64_t)rc;
        out += rc;
    }

    libssh2_sftp_close(handle);
    return remaining == 0 ? 1 : 0;
}

int SftpClient::Put(const std::string &inputfile, const std::string &path, uint64_t offset)
{
    if (!connected || !sftp)
        return 0;

    FILE *file = fopen(inputfile.c_str(), "rb");
    if (!file)
    {
        setResponse(lang_strings[STR_FAIL_UPLOAD_MSG]);
        return 0;
    }

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open_ex(
        sftp, full.c_str(), (unsigned int)full.size(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
        LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR |
        LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH,
        LIBSSH2_SFTP_OPENFILE);
    if (!handle)
    {
        fclose(file);
        setResponse(lang_strings[STR_FAIL_UPLOAD_MSG]);
        return 0;
    }

    if (offset > 0)
    {
        libssh2_sftp_seek64(handle, offset);
        fseeko(file, (off_t)offset, SEEK_SET);
    }

    std::vector<char> buffer(kTransferBufferSize);

    while (true)
    {
        if (stop_activity)
        {
            setResponse(lang_strings[STR_CANCEL_ACTION_MSG]);
            fclose(file);
            libssh2_sftp_close(handle);
            return 0;
        }

        size_t read_count = fread(buffer.data(), 1, buffer.size(), file);
        if (read_count == 0)
        {
            if (ferror(file))
            {
                setResponse(lang_strings[STR_FAIL_UPLOAD_MSG]);
                fclose(file);
                libssh2_sftp_close(handle);
                return 0;
            }
            break;
        }

        char *ptr = buffer.data();
        size_t left = read_count;

        while (left > 0)
        {
            ssize_t written = libssh2_sftp_write(handle, ptr, left);
            if (written < 0)
            {
                setResponse(lang_strings[STR_FAIL_UPLOAD_MSG]);
                fclose(file);
                libssh2_sftp_close(handle);
                return 0;
            }
            ptr += written;
            left -= (size_t)written;
            bytes_transfered += (int64_t)written;
        }
    }

    fclose(file);
    libssh2_sftp_close(handle);
    setResponse(lang_strings[STR_UPLOADING]);
    return 1;
}

int SftpClient::Rename(const std::string &src, const std::string &dst)
{
    if (!connected || !sftp)
        return 0;

    std::string full_src = getFullPath(src);
    std::string full_dst = getFullPath(dst);

    int rc = libssh2_sftp_rename_ex(sftp,
                                    full_src.c_str(), (unsigned int)full_src.size(),
                                    full_dst.c_str(), (unsigned int)full_dst.size(),
                                    LIBSSH2_SFTP_RENAME_OVERWRITE |
                                    LIBSSH2_SFTP_RENAME_ATOMIC |
                                    LIBSSH2_SFTP_RENAME_NATIVE);
    if (rc == 0)
        return 1;

    setResponse(lang_strings[STR_UNSUPPORTED_OPERATION_MSG]);
    return 0;
}

int SftpClient::Delete(const std::string &path)
{
    if (!connected || !sftp)
        return 0;

    std::string full = getFullPath(path);
    int rc = libssh2_sftp_unlink_ex(sftp, full.c_str(), (unsigned int)full.size());
    if (rc == 0)
        return 1;

    setResponse(lang_strings[STR_FAIL_DEL_FILE_MSG]);
    return 0;
}

int SftpClient::Copy(const std::string &from, const std::string &to)
{
    setResponse(lang_strings[STR_UNSUPPORTED_OPERATION_MSG]);
    return 0;
}

int SftpClient::Move(const std::string &from, const std::string &to)
{
    return Rename(from, to);
}

bool SftpClient::FileExists(const std::string &path)
{
    int64_t size = 0;
    return Size(path, &size) == 1;
}

std::vector<DirEntry> SftpClient::ListDir(const std::string &path)
{
    std::vector<DirEntry> out;

    if (!connected || !sftp)
        return out;

    DirEntry entry;
    Util::SetupPreviousFolder(path, &entry);
    out.push_back(entry);

    std::string full = getFullPath(path);
    LIBSSH2_SFTP_HANDLE *dir = libssh2_sftp_opendir(sftp, full.c_str());
    if (!dir)
        return out;

    while (true)
    {
        char filename[512];
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        int rc = libssh2_sftp_readdir_ex(
            dir,
            filename, sizeof(filename),
            nullptr, 0,
            &attrs);

        if (rc <= 0)
            break;

        if (filename[0] == '\0' || strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
            continue;

        DirEntry e;
        memset(&e, 0, sizeof(e));

        std::string dir_path = path;
        dir_path = Util::Trim(dir_path, " ");
        if (dir_path.empty())
            dir_path = "/";

        snprintf(e.directory, sizeof(e.directory), "%s", dir_path.c_str());
        snprintf(e.name, sizeof(e.name), "%s", filename);

        std::string combined = GetPath(dir_path, filename);
        snprintf(e.path, sizeof(e.path), "%s", combined.c_str());

        e.isDir = false;
        e.isLink = false;
        e.selectable = true;
        e.file_size = 0;

        if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
        {
            if (LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
                e.isDir = true;
        }
        if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE)
            e.file_size = (uint64_t)attrs.filesize;

        DirEntry::SetDisplaySize(&e);
        snprintf(e.display_date, sizeof(e.display_date), "%s", "");

        out.push_back(e);
    }

    libssh2_sftp_closedir(dir);
    DirEntry::Sort(out);
    return out;
}

std::string SftpClient::GetPath(std::string ppath1, std::string ppath2)
{
    std::string path1 = ppath1;
    std::string path2 = ppath2;
    path1 = Util::Rtrim(Util::Trim(path1, " "), "/");
    path2 = Util::Rtrim(Util::Trim(path2, " "), "/");
    if (path1.empty())
        path1 = "/";
    if (path1[path1.size() - 1] != '/')
        path1 = path1 + "/";
    path1 = path1 + path2;
    Util::ReplaceAll(path1, "//", "/");
    return path1;
}

int SftpClient::GetRange(void *fp, void *buffer, uint64_t size, uint64_t offset)
{
    if (!connected || !sftp || !fp || !buffer || size == 0)
        return 0;

    LIBSSH2_SFTP_HANDLE *handle = static_cast<LIBSSH2_SFTP_HANDLE *>(fp);
    libssh2_sftp_seek64(handle, offset);

    uint64_t remaining = size;
    char *out = static_cast<char *>(buffer);

    while (remaining > 0)
    {
        ssize_t rc = libssh2_sftp_read(handle, out, (size_t)remaining);
        if (rc <= 0)
            break;
        remaining -= (uint64_t)rc;
        out += rc;
    }

    return remaining == 0 ? 1 : 0;
}

void *SftpClient::Open(const std::string &path, int flags)
{
    if (!connected || !sftp)
        return nullptr;

    std::string full = getFullPath(path);
    unsigned long open_flags = 0;
    unsigned long mode = 0;

    if (flags & 1)
    {
        open_flags |= LIBSSH2_FXF_READ;
    }
    if (flags & 2)
    {
        open_flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT;
        mode = LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR |
               LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH;
    }

    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open_ex(
        sftp, full.c_str(), (unsigned int)full.size(),
        open_flags,
        mode,
        LIBSSH2_SFTP_OPENFILE);

    return handle;
}

void SftpClient::Close(void *fp)
{
    if (!fp)
        return;

    LIBSSH2_SFTP_HANDLE *handle = static_cast<LIBSSH2_SFTP_HANDLE *>(fp);
    libssh2_sftp_close(handle);
}

bool SftpClient::IsConnected()
{
    return connected;
}

bool SftpClient::Ping()
{
    return connected;
}

const char *SftpClient::LastResponse()
{
    return response;
}

int SftpClient::Quit()
{
    if (!connected)
        return 1;

    if (sftp)
    {
        libssh2_sftp_shutdown(sftp);
        sftp = nullptr;
    }

    if (session)
    {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        session = nullptr;
    }

    if (sock >= 0)
    {
        close(sock);
        sock = -1;
    }

    connected = false;
    return 1;
}

ClientType SftpClient::clientType()
{
    return CLIENT_TYPE_SFTP;
}

uint32_t SftpClient::SupportedActions()
{
    return REMOTE_ACTION_ALL ^ REMOTE_ACTION_CUT ^ REMOTE_ACTION_COPY ^ REMOTE_ACTION_PASTE ^ REMOTE_ACTION_RAW_READ;
}
