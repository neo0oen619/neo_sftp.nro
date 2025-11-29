#include <fstream>
#include <regex>
#include <algorithm>
#include "common.h"
#include "clients/remote_client.h"
#include "clients/webdav.h"
#include "pugixml/pugiext.hpp"
#include "fs.h"
#include "lang.h"
#include "config.h"
#include "util.h"
#include "windows.h"
#include "logger.h"

static const char *months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

namespace
{
    struct WebDAVChunkTask
    {
        std::string url;
        std::string user;
        std::string pass;
        std::string rangeHeader;
        int64_t start = 0;
        int64_t end = 0;
        long httpCode = 0;
        std::string err;
        std::string data;
        bool ok = false;
    };

    void WebDAVChunkDownloadThread(void *argp)
    {
        WebDAVChunkTask *task = static_cast<WebDAVChunkTask *>(argp);
        if (!task)
            return;

        CHTTPClient http([](const std::string &){});
        // Match BaseClient::Connect setup: relaxed TLS verification and
        // optional basic auth, plus the shared CA file.
        http.SetBasicAuth(task->user, task->pass);
        http.InitSession(false, CHTTPClient::SettingsFlag::NO_FLAGS);
        http.SetCertificateFile(CACERT_FILE);

        CHTTPClient::HttpResponse res;
        CHTTPClient::HeadersMap headers;
        if (!task->rangeHeader.empty())
            headers["Range"] = task->rangeHeader;

        if (!http.Get(task->url, headers, res))
        {
            task->err = res.errMessage;
            task->httpCode = res.iCode;
            task->ok = false;
            Logger::Logf("WEBDAV GET parallel range error url=%s range=%s err=%s",
                         task->url.c_str(),
                         task->rangeHeader.c_str(),
                         res.errMessage.c_str());
            return;
        }

        task->httpCode = res.iCode;
        if (res.iCode != 206)
        {
            task->err = "unexpected http code";
            Logger::Logf("WEBDAV GET parallel unexpected code url=%s range=%s code=%ld",
                         task->url.c_str(),
                         task->rangeHeader.c_str(),
                         res.iCode);
            task->ok = false;
            return;
        }

        if (res.strBody.empty())
        {
            task->err = "empty body";
            Logger::Logf("WEBDAV GET parallel empty body url=%s range=%s",
                         task->url.c_str(),
                         task->rangeHeader.c_str());
            task->ok = false;
            return;
        }

        task->data.swap(res.strBody);
        task->ok = true;
    }
}

std::string WebDAVClient::GetHttpUrl(std::string url)
{
    std::string http_url = std::regex_replace(url, std::regex("webdav://"), "http://");
    http_url = std::regex_replace(http_url, std::regex("webdavs://"), "https://");
    return http_url;
}

int WebDAVClient::Connect(const std::string &host, const std::string &user, const std::string &pass)
{
    std::string url = GetHttpUrl(host);
    return BaseClient::Connect(url, user, pass);
}

bool WebDAVClient::PropFind(const std::string &path, int depth, CHTTPClient::HttpResponse &res)
{
    CHTTPClient::HeadersMap headers;
    headers["Accept"] = "*/*";
    headers["Depth"] = std::to_string(depth);
    std::string encoded_path = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));

    return client->CustomRequest("PROPFIND", encoded_path, headers, res);
}

int WebDAVClient::Size(const std::string &path, int64_t *size)
{
    CHTTPClient::HttpResponse res;

    Logger::Logf("WEBDAV Size path='%s'", path.c_str());

    if (PropFind(path, 1, res))
    {
        pugi::xml_document document;
        document.load_buffer(res.strBody.data(), res.strBody.size());
        auto multistatus = document.select_node("*[local-name()='multistatus']").node();
        auto responses = multistatus.select_nodes("*[local-name()='response']");

        // Normalize target path to the logical path the UI uses (without
        // any WebDAV base path like "/dav"). This makes it match the
        // href values returned by SFTPGo and other servers that expose
        // physical paths (eg "/F:2TB/...") directly.
        std::string target_path_without_sep = path;
        Util::Trim(target_path_without_sep, " ");
        Util::Rtrim(target_path_without_sep, "/");
        if (target_path_without_sep.empty())
            target_path_without_sep = "/";

        Logger::Logf("WEBDAV Size normalized target_path='%s', responses=%zu",
                     target_path_without_sep.c_str(), responses.size());

        for (auto response : responses)
        {
            pugi::xml_node href = response.node().select_node("*[local-name()='href']").node();
            if (!href || !href.first_child())
                continue;

            std::string resource_path = CHTTPClient::DecodeUrl(href.first_child().value(), true);
            auto resource_path_without_sep = resource_path.erase(resource_path.find_last_not_of('/') + 1);
            // Strip any WebDAV base path (eg "/dav") from the beginning,
            // so URLs like "/dav/F:2TB/..." match our logical path
            // "/F:2TB/...".
            if (!this->base_path.empty() && this->base_path != "/")
            {
                if (resource_path_without_sep.compare(0, this->base_path.size(), this->base_path) == 0)
                {
                    resource_path_without_sep.erase(0, this->base_path.size());
                    if (resource_path_without_sep.empty())
                        resource_path_without_sep = "/";
                }
            }

            Logger::Logf("WEBDAV Size href='%s' -> resource_path='%s' target='%s'",
                         href.first_child().value(),
                         resource_path_without_sep.c_str(),
                         target_path_without_sep.c_str());

            if (resource_path_without_sep != target_path_without_sep)
                continue;

            auto propstat = response.node().select_node("*[local-name()='propstat']").node();
            auto prop = propstat.select_node("*[local-name()='prop']").node();
            auto len_node = prop.select_node("*[local-name()='getcontentlength']").node();
            if (!len_node || !len_node.first_child())
                continue;

            std::string content_length = len_node.first_child().value();
            *size = atoll(content_length.c_str());
            return 1;
        }
    }
    else
    {
        sprintf(this->response, "%s", res.errMessage.c_str());
        Logger::Logf("WEBDAV Size PROPFIND failed err=%s", this->response);
    }

    return 0;
}

int WebDAVClient::Get(const std::string &outputfile, const std::string &path, uint64_t offset)
{
    bytes_transfered = 0;
    prev_tick = Util::GetTick();

    // First, try to get the full size via PROPFIND so we can download
    // in smaller HTTP range chunks (more robust with Tailscale/Funnel).
    int64_t size = 0;
    if (!Size(path, &size) || size <= 0)
    {
        Logger::Logf("WEBDAV GET unable to determine size for path='%s', falling back to single GET",
                     path.c_str());
        // Fall back to the simple one-shot GET path for small files.
        std::string encoded_url_fallback = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));

        CHTTPClient::HttpResponse res_fallback;
        CHTTPClient::HeadersMap headers_fallback;

        if (!client->Get(encoded_url_fallback, headers_fallback, res_fallback))
        {
            sprintf(this->response, "%s", res_fallback.errMessage.c_str());
            Logger::Logf("WEBDAV GET fallback error url=%s err=%s",
                         encoded_url_fallback.c_str(), res_fallback.errMessage.c_str());
            return 0;
        }

        if (!HTTP_SUCCESS(res_fallback.iCode))
        {
            sprintf(this->response, "%ld - %s", res_fallback.iCode, lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            Logger::Logf("WEBDAV GET fallback http error url=%s code=%ld",
                         encoded_url_fallback.c_str(), res_fallback.iCode);
            return 0;
        }

        FILE *file_fallback = std::fopen(outputfile.c_str(), "wb");
        if (!file_fallback)
        {
            sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            Logger::Logf("WEBDAV GET fallback fopen failed path=%s", outputfile.c_str());
            return 0;
        }

        size_t written_fb = std::fwrite(res_fallback.strBody.data(), 1, res_fallback.strBody.size(), file_fallback);
        std::fclose(file_fallback);

        if (written_fb != res_fallback.strBody.size())
        {
            sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            Logger::Logf("WEBDAV GET fallback write failed path=%s expected=%zu written=%zu",
                         outputfile.c_str(), res_fallback.strBody.size(), written_fb);
            return 0;
        }

        bytes_to_download = static_cast<int64_t>(res_fallback.strBody.size());
        bytes_transfered = bytes_to_download;

        Logger::Logf("WEBDAV GET fallback done url=%s code=%ld bytes=%zu",
                     encoded_url_fallback.c_str(), res_fallback.iCode, res_fallback.strBody.size());
        return 1;
    }

    bytes_to_download = size;
    bytes_transfered = 0;

    std::string encoded_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));

    // Use configurable HTTP range chunk size (in MiB), defaulting to 8 MiB.
    // This keeps per-request overhead low over high-latency links while
    // still fitting comfortably in Switch memory. Value is clamped in
    // CONFIG::LoadConfig(), but guard here as well.
    int chunk_mb = webdav_chunk_size_mb;
    if (chunk_mb < 1)
        chunk_mb = 1;
    else if (chunk_mb > 16)
        chunk_mb = 16;
    const int64_t chunk_size = static_cast<int64_t>(chunk_mb) * 1024 * 1024;

    int parallel = webdav_parallel_connections;
    if (parallel < 1)
        parallel = 1;
    else if (parallel > 4)
        parallel = 4;

    Logger::Logf("WEBDAV GET (ranged) url=%s -> output=%s size=%lld chunk_size=%lld parallel=%d",
                 encoded_url.c_str(),
                 outputfile.c_str(),
                 static_cast<long long>(size),
                 static_cast<long long>(chunk_size),
                 parallel);

    // Only attempt the more aggressive parallel ranged path when:
    // - The file is reasonably large (at least a couple of chunks).
    // - The server clearly supports HTTP Range requests.
    const bool wants_parallel = (parallel > 1 && size > chunk_size * 2);
    if (wants_parallel && ProbeRangeSupport(encoded_url))
    {
        Logger::Logf("WEBDAV GET using parallel ranged download url=%s", encoded_url.c_str());
        return GetRangedParallel(outputfile, encoded_url, size, chunk_size, parallel);
    }

    Logger::Logf("WEBDAV GET using sequential ranged download url=%s", encoded_url.c_str());
    return GetRangedSequential(outputfile, encoded_url, size, chunk_size);
}

bool WebDAVClient::ProbeRangeSupport(const std::string &encoded_url)
{
    CHTTPClient::HttpResponse res;
    CHTTPClient::HeadersMap headers;
    headers["Range"] = "bytes=0-0";

    if (!client->Get(encoded_url, headers, res))
    {
        Logger::Logf("WEBDAV GET range probe error url=%s err=%s",
                     encoded_url.c_str(), res.errMessage.c_str());
        return false;
    }

    if (res.iCode == 206)
    {
        Logger::Logf("WEBDAV GET range probe ok url=%s code=%ld",
                     encoded_url.c_str(), res.iCode);
        return true;
    }

    Logger::Logf("WEBDAV GET range probe unsupported url=%s code=%ld",
                 encoded_url.c_str(), res.iCode);
    return false;
}

int WebDAVClient::GetRangedSequential(const std::string &outputfile,
                                      const std::string &encoded_url,
                                      int64_t size,
                                      int64_t chunk_size)
{
    FILE *file = std::fopen(outputfile.c_str(), "wb");
    if (!file)
    {
        sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        Logger::Logf("WEBDAV GET fopen failed path=%s", outputfile.c_str());
        return 0;
    }

    int64_t offset_bytes = 0;
    long last_code = 0;

    while (offset_bytes < size)
    {
        int64_t end = offset_bytes + chunk_size - 1;
        if (end >= size)
            end = size - 1;

        char range_header[64];
        std::snprintf(range_header, sizeof(range_header), "bytes=%lld-%lld",
                      static_cast<long long>(offset_bytes),
                      static_cast<long long>(end));

        CHTTPClient::HeadersMap headers;
        headers["Range"] = range_header;

        CHTTPClient::HttpResponse res;
        if (!client->Get(encoded_url, headers, res))
        {
            sprintf(this->response, "%s", res.errMessage.c_str());
            Logger::Logf("WEBDAV GET range error url=%s range=%s err=%s",
                         encoded_url.c_str(), range_header, res.errMessage.c_str());
            std::fclose(file);
            return 0;
        }

        last_code = res.iCode;
        if (!(res.iCode == 206 || res.iCode == 200))
        {
            sprintf(this->response, "%ld - %s", res.iCode, lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            Logger::Logf("WEBDAV GET range http error url=%s range=%s code=%ld",
                         encoded_url.c_str(), range_header, res.iCode);
            std::fclose(file);
            return 0;
        }

        if (res.strBody.empty())
        {
            Logger::Logf("WEBDAV GET range empty body url=%s range=%s", encoded_url.c_str(), range_header);
            break;
        }

        size_t written = std::fwrite(res.strBody.data(), 1, res.strBody.size(), file);
        if (written != res.strBody.size())
        {
            sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            Logger::Logf("WEBDAV GET range write failed path=%s expected=%zu written=%zu",
                         outputfile.c_str(), res.strBody.size(), written);
            std::fclose(file);
            return 0;
        }

        offset_bytes += static_cast<int64_t>(res.strBody.size());
        bytes_transfered = offset_bytes;

        Logger::Logf("WEBDAV GET range ok url=%s range=%s code=%ld chunk_bytes=%zu total_bytes=%lld",
                     encoded_url.c_str(), range_header, res.iCode,
                     res.strBody.size(), static_cast<long long>(offset_bytes));

        // If server ignored Range and returned the full file with 200,
        // we are done after the first iteration.
        if (res.iCode == 200)
        {
            break;
        }
    }

    std::fclose(file);

    if (offset_bytes <= 0)
    {
        sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        Logger::Logf("WEBDAV GET ranged download produced no data url=%s", encoded_url.c_str());
        return 0;
    }

    Logger::Logf("WEBDAV GET ranged done url=%s code=%ld bytes=%lld",
                 encoded_url.c_str(), last_code, static_cast<long long>(offset_bytes));
    return 1;
}

int WebDAVClient::GetRangedParallel(const std::string &outputfile,
                                    const std::string &encoded_url,
                                    int64_t size,
                                    int64_t chunk_size,
                                    int parallel)
{
    FILE *file = std::fopen(outputfile.c_str(), "wb");
    if (!file)
    {
        sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        Logger::Logf("WEBDAV GET parallel fopen failed path=%s", outputfile.c_str());
        return 0;
    }

    bytes_transfered = 0;
    long last_code = 0;

    int64_t scheduled_offset = 0;

    while (scheduled_offset < size)
    {
        std::vector<WebDAVChunkTask> tasks;
        std::vector<Thread> threads;

        int current_parallel = 0;
        while (current_parallel < parallel && scheduled_offset < size)
        {
            int64_t start = scheduled_offset;
            int64_t end = start + chunk_size - 1;
            if (end >= size)
                end = size - 1;

            WebDAVChunkTask task;
            task.url = encoded_url;
            task.user = http_username;
            task.pass = http_password;
            task.start = start;
            task.end = end;

            char range_header[64];
            std::snprintf(range_header, sizeof(range_header), "bytes=%lld-%lld",
                          static_cast<long long>(start),
                          static_cast<long long>(end));
            task.rangeHeader = range_header;

            tasks.push_back(std::move(task));

            scheduled_offset = end + 1;
            ++current_parallel;
        }

        threads.resize(tasks.size());
        bool threadError = false;

        for (size_t i = 0; i < tasks.size(); ++i)
        {
            Result rc = threadCreate(&threads[i],
                                     WebDAVChunkDownloadThread,
                                     &tasks[i],
                                     nullptr,
                                     0x10000,
                                     0x3B,
                                     -2);
            if (R_FAILED(rc))
            {
                Logger::Logf("WEBDAV GET parallel failed to create thread url=%s range=%s rc=0x%08x",
                             encoded_url.c_str(),
                             tasks[i].rangeHeader.c_str(),
                             rc);
                threadError = true;
                break;
            }

            threadStart(&threads[i]);
        }

        for (size_t i = 0; i < threads.size(); ++i)
        {
            if (threads[i].handle != 0)
            {
                threadWaitForExit(&threads[i]);
                threadClose(&threads[i]);
            }
        }

        if (threadError)
        {
            std::fclose(file);
            sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
            return 0;
        }

        for (const auto &task : tasks)
        {
            if (!task.ok)
            {
                std::fclose(file);
                if (!task.err.empty())
                    snprintf(this->response, sizeof(this->response), "%s", task.err.c_str());
                else
                    sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);

                Logger::Logf("WEBDAV GET parallel chunk failed url=%s range=%s code=%ld err=%s",
                             encoded_url.c_str(),
                             task.rangeHeader.c_str(),
                             task.httpCode,
                             task.err.c_str());
                return 0;
            }
        }

        std::sort(tasks.begin(), tasks.end(),
                  [](const WebDAVChunkTask &a, const WebDAVChunkTask &b)
                  {
                      return a.start < b.start;
                  });

        for (auto &task : tasks)
        {
            if (task.data.empty())
                continue;

            size_t written = std::fwrite(task.data.data(), 1, task.data.size(), file);
            if (written != task.data.size())
            {
                sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
                Logger::Logf("WEBDAV GET parallel write failed path=%s expected=%zu written=%zu",
                             outputfile.c_str(), task.data.size(), written);
                std::fclose(file);
                return 0;
            }

            bytes_transfered += static_cast<int64_t>(task.data.size());
            last_code = task.httpCode;

            Logger::Logf("WEBDAV GET parallel chunk ok url=%s range=%s code=%ld chunk_bytes=%zu total_bytes=%lld",
                         encoded_url.c_str(),
                         task.rangeHeader.c_str(),
                         task.httpCode,
                         task.data.size(),
                         static_cast<long long>(bytes_transfered));
        }
    }

    std::fclose(file);

    if (bytes_transfered <= 0)
    {
        sprintf(this->response, "%s", lang_strings[STR_FAIL_DOWNLOAD_MSG]);
        Logger::Logf("WEBDAV GET ranged-parallel produced no data url=%s", encoded_url.c_str());
        return 0;
    }

    Logger::Logf("WEBDAV GET ranged-parallel done url=%s code=%ld bytes=%lld parallel=%d",
                 encoded_url.c_str(),
                 last_code,
                 static_cast<long long>(bytes_transfered),
                 parallel);
    return 1;
}

std::vector<DirEntry> WebDAVClient::ListDir(const std::string &path)
{
    CHTTPClient::HttpResponse res;
    std::vector<DirEntry> out;
    DirEntry entry;
    Util::SetupPreviousFolder(path, &entry);
    out.push_back(entry);

    Logger::Logf("WEBDAV ListDir path='%s'", path.c_str());

    if (PropFind(path, 1, res))
    {
        pugi::xml_document document;
        document.load_buffer(res.strBody.data(), res.strBody.size());
        auto multistatus = document.select_node("*[local-name()='multistatus']").node();
        auto responses = multistatus.select_nodes("*[local-name()='response']");

        // Normalize the current logical path (what the user sees in the UI)
        // without any WebDAV base path (eg "/dav").
        std::string target_path_without_sep = path;
        Util::Trim(target_path_without_sep, " ");
        Util::Rtrim(target_path_without_sep, "/");
        if (target_path_without_sep.empty())
            target_path_without_sep = "/";

        Logger::Logf("WEBDAV ListDir normalized target_path='%s', responses=%zu",
                     target_path_without_sep.c_str(), responses.size());

        for (auto response : responses)
        {
            pugi::xml_node href = response.node().select_node("*[local-name()='href']").node();
            if (!href || !href.first_child())
                continue;

            std::string resource_path = CHTTPClient::DecodeUrl(href.first_child().value(), true);
            auto resource_path_without_sep = resource_path.erase(resource_path.find_last_not_of('/') + 1);
            if (!this->base_path.empty() && this->base_path != "/")
            {
                if (resource_path_without_sep.compare(0, this->base_path.size(), this->base_path) == 0)
                {
                    resource_path_without_sep.erase(0, this->base_path.size());
                    if (resource_path_without_sep.empty())
                        resource_path_without_sep = "/";
                }
            }

            Logger::Logf("WEBDAV ListDir href='%s' -> resource_path='%s'",
                         href.first_child().value(),
                         resource_path_without_sep.c_str());

            if (resource_path_without_sep == target_path_without_sep)
                continue;

            size_t pos2 = resource_path_without_sep.find_last_of('/');
            auto name = resource_path_without_sep.substr(pos2 + 1);
            auto propstat = response.node().select_node("*[local-name()='propstat']").node();
            auto prop = propstat.select_node("*[local-name()='prop']").node();

            std::string creation_date;
            std::string content_length;
            std::string m_date;
            std::string resource_type;

            auto cd_node = prop.select_node("*[local-name()='creationdate']").node();
            if (cd_node && cd_node.first_child())
                creation_date = cd_node.first_child().value();

            auto len_node = prop.select_node("*[local-name()='getcontentlength']").node();
            if (len_node && len_node.first_child())
                content_length = len_node.first_child().value();

            auto md_node = prop.select_node("*[local-name()='getlastmodified']").node();
            if (md_node && md_node.first_child())
                m_date = md_node.first_child().value();

            auto rt_node = prop.select_node("*[local-name()='resourcetype']").node();
            if (rt_node && rt_node.first_child())
                resource_type = rt_node.first_child().name();

            DirEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.selectable = true;
            sprintf(entry.directory, "%s", path.c_str());
            sprintf(entry.name, "%s", name.c_str());

            if (path.length() == 1 and path[0] == '/')
            {
                sprintf(entry.path, "%s%s", path.c_str(), name.c_str());
            }
            else
            {
                sprintf(entry.path, "%s/%s", path.c_str(), name.c_str());
            }

            entry.isDir = resource_type.find("collection") != std::string::npos;
            entry.file_size = 0;
            if (!entry.isDir)
            {
                entry.file_size = atoll(content_length.c_str());
                DirEntry::SetDisplaySize(&entry);
            }
            else
            {
                sprintf(entry.display_size, "%s", lang_strings[STR_FOLDER]);
            }

            char modified_date[32];
            char *p_char = NULL;
            sprintf(modified_date, "%s", m_date.c_str());
            p_char = strchr(modified_date, ' ');
            if (p_char)
            {
                char month[5];
                sscanf(p_char, "%d %s %d %d:%d:%d", &entry.modified.day, month, &entry.modified.year, &entry.modified.hours, &entry.modified.minutes, &entry.modified.seconds);
                for (int k = 0; k < 12; k++)
                {
                    if (strcmp(month, months[k]) == 0)
                    {
                        entry.modified.month = k + 1;
                        break;
                    }
                }
            }
            out.push_back(entry);
        }
    }
    else
    {
        sprintf(this->response, "%s", res.errMessage.c_str());
        Logger::Logf("WEBDAV ListDir PROPFIND failed err=%s", this->response);
        return out;
    }

    return out;
}

int WebDAVClient::Put(const std::string &inputfile, const std::string &path, uint64_t offset)
{
    size_t bytes_remaining = FS::GetSize(inputfile);
    bytes_transfered = 0;
    prev_tick = Util::GetTick();

    client->SetProgressFnCallback(&bytes_transfered, UploadProgressCallback);
    std::string encode_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));
    long status;

    if (client->UploadFile(inputfile, encode_url, status))
    {
        if (HTTP_SUCCESS(status))
        {
            return 1;
        }
    }

    return 0;
}

int WebDAVClient::Mkdir(const std::string &path)
{
    CHTTPClient::HeadersMap headers;
    CHTTPClient::HttpResponse res;

    headers["Accept"] =  "*/*";
    headers["Connection"] = "Keep-Alive";
    std::string encode_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));

    if (client->CustomRequest("MKCOL", encode_url, headers, res))
    {
        if (HTTP_SUCCESS(res.iCode))
            return 1;
    }

    return 0;
}

int WebDAVClient::Rmdir(const std::string &path, bool recursive)
{
    return Delete(path);
}

int WebDAVClient::Rename(const std::string &src, const std::string &dst)
{
    return Move(src, dst);
}

int WebDAVClient::Delete(const std::string &path)
{
    CHTTPClient::HeadersMap headers;
    CHTTPClient::HttpResponse res;

    headers["Accept"] =  "*/*";
    headers["Connection"] = "Keep-Alive";
    std::string encode_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(path));

    if (client->CustomRequest("DELETE", encode_url, headers, res))
    {
        if (HTTP_SUCCESS(res.iCode))
            return 1;
    }
    
    return 0;

}

int WebDAVClient::Copy(const std::string &from, const std::string &to)
{
    CHTTPClient::HeadersMap headers;
    CHTTPClient::HttpResponse res;

    headers["Accept"] =  "*/*";
    headers["Destination"] = GetFullPath(to);
    std::string encode_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(from));

    if (client->CustomRequest("COPY", encode_url, headers, res))
    {
        if (HTTP_SUCCESS(res.iCode))
            return 1;
    }

    return 0;
}

int WebDAVClient::Move(const std::string &from, const std::string &to)
{
    CHTTPClient::HeadersMap headers;
    CHTTPClient::HttpResponse res;

    headers["Accept"] =  "*/*";
    headers["Destination"] = GetFullPath(to);
    std::string encode_url = this->host_url + CHTTPClient::EncodeUrl(GetFullPath(from));

    if (client->CustomRequest("MOVE", encode_url, headers, res))
    {
        if (HTTP_SUCCESS(res.iCode))
            return 1;
    }

    return 0;
}

ClientType WebDAVClient::clientType()
{
    return CLIENT_TYPE_WEBDAV;
}

uint32_t WebDAVClient::SupportedActions()
{
    return REMOTE_ACTION_ALL ^ REMOTE_ACTION_RAW_READ;
}
