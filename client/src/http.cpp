#include "http_rules.hpp"
#include "http_state.hpp"
#include "resources.hpp"
#include <mutex>
#include <set>
namespace wwe {
namespace {
std::mutex state_lock;
HttpHandles handles;
std::set<std::wstring> targets = {L"508223012e5a5ff19f30a391b2bdadc0.my.2k.com",
                                  L"wwe2k22-peg.2ksports.com",
                                  L"wwe2k22-ws.2ksports.com"};
size_t learned = 0;
std::wstring rest_session;
decltype(&WinHttpConnect) real_connect = nullptr;
decltype(&WinHttpOpenRequest) real_request = nullptr;
decltype(&WinHttpAddRequestHeaders) real_headers = nullptr;
decltype(&WinHttpSendRequest) real_send = nullptr;
decltype(&WinHttpCloseHandle) real_close = nullptr;
decltype(&WinHttpSetOption) real_option = nullptr;
constexpr DWORD insecure_flags =
    SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | 0x00010000;
std::wstring lower(std::wstring text) {
  for (auto &c : text)
    c = http_rules::lower(c);
  return text;
}
HINTERNET WINAPI connect(HINTERNET session, LPCWSTR name, INTERNET_PORT port,
                         DWORD reserved) noexcept {
  if (!hooks_ready())
    return real_connect(session, name, port, reserved);
  try {
    DWORD before = GetLastError();
    auto host = lower(unicode(name, 254));
    bool redirect = false;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      redirect = targets.count(host) != 0;
    }
    bool local = redirect || (host == config.host && port == config.port);
    SetLastError(before);
    InternetHandle result(
        real_connect(session, redirect ? config.host.c_str() : name,
                     redirect ? config.port : port, reserved));
    DWORD error = GetLastError();
    if (result) {
      bool accepted = false;
      {
        std::lock_guard<std::mutex> lock(state_lock);
        accepted = handles.remember_connection(result.get(), local);
      }
      if (!accepted) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
      }
    }
    SetLastError(error);
    return result.release();
  } catch (...) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return nullptr;
  }
}
HINTERNET WINAPI request(HINTERNET connection, LPCWSTR verb, LPCWSTR path,
                         LPCWSTR version, LPCWSTR referer, LPCWSTR *accept,
                         DWORD flags) noexcept {
  if (!hooks_ready())
    return real_request(connection, verb, path, version, referer, accept,
                        flags);
  try {
    DWORD before = GetLastError();
    bool local = false;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      local = handles.connection(connection);
    }
    bool asset = local && config.content &&
                 http_rules::asset(unicode(verb, 8), unicode(path, 160));
    if (local) {
      if (config.https)
        flags |= WINHTTP_FLAG_SECURE;
      else
        flags &= ~WINHTTP_FLAG_SECURE;
    }
    SetLastError(before);
    InternetHandle result(
        real_request(connection, verb, path, version, referer, accept, flags));
    DWORD error = GetLastError();
    if (result && local && config.content && unicode(verb, 8) == L"POST" &&
        unicode(path, 160) == L"/api/ContentMetaGet" &&
        !real_headers(result.get(), L"X-WWE-Native-Images: 1\r\n", (DWORD)-1,
                      WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
      return nullptr;
    if (result) {
      bool accepted = false;
      {
        std::lock_guard<std::mutex> lock(state_lock);
        accepted = handles.remember_request(result.get(), local, asset);
      }
      if (!accepted) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
      }
    }
    SetLastError(error);
    return result.release();
  } catch (...) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return nullptr;
  }
}
std::optional<std::wstring> header_text(const wchar_t *text, DWORD length) {
  if (!text)
    return std::wstring{};
  if (length == (DWORD)-1) {
    auto value = unicode(text, 8192);
    if (value.empty()) {
      wchar_t first = 0;
      if (!read(text, first) || first)
        return {};
    }
    return value;
  }
  if (length > 8192)
    return {};
  std::wstring value(length, L'\0');
  if (!read_memory(text, value.data(), length * sizeof(wchar_t)))
    return {};
  return value;
}
BOOL WINAPI headers(HINTERNET request, LPCWSTR text, DWORD length,
                    DWORD flags) noexcept {
  if (!hooks_ready())
    return real_headers(request, text, length, flags);
  try {
    DWORD before = GetLastError();
    bool observe = false, asset = false;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      auto entry = handles.request(request);
      observe = entry && !(*entry);
      asset = entry && *entry;
    }
    SetLastError(before);
    BOOL result = real_headers(request, text, length, flags);
    DWORD error = GetLastError();
    if (result && observe && config.content)
      observe_headers(text, length);
    if (result && asset) {
      auto value = header_text(text, length);
      if (value && http_rules::session(*value)) {
        std::lock_guard<std::mutex> lock(state_lock);
        handles.injected(request, handles.ticket(request), false);
      }
    }
    SetLastError(error);
    return result;
  } catch (...) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}
BOOL WINAPI send(HINTERNET request, LPCWSTR text, DWORD length, LPVOID data,
                 DWORD size, DWORD total, DWORD_PTR context) noexcept {
  if (!hooks_ready())
    return real_send(request, text, length, data, size, total, context);
  try {
    DWORD before = GetLastError();
    std::optional<bool> entry;
    std::wstring session;
    bool injected = false;
    HttpHandles::Ticket ticket;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      entry = handles.request(request);
      if (entry && *entry) {
        session = rest_session;
        injected = handles.injected(request);
        ticket = handles.ticket(request);
      }
    }
    if (entry) {
      // Private auth/session headers must never follow automatic redirects.
      DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
      if (!real_option(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect,
                       sizeof(redirect)))
        return FALSE;
      if (config.https) {
        DWORD secure = 0, bytes = sizeof(secure);
        if (!real_option(request, WINHTTP_OPTION_SECURITY_FLAGS, &secure,
                         sizeof(secure)) ||
            !WinHttpQueryOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &secure,
                                &bytes))
          return FALSE;
        if (secure & insecure_flags) {
          SetLastError(ERROR_WINHTTP_SECURE_FAILURE);
          return FALSE;
        }
      }
      if (!config.key_header.empty() &&
          !real_headers(request, config.key_header.c_str(), (DWORD)-1,
                        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
        return FALSE;
      if (*entry) {
        auto additional = header_text(text, length);
        bool supplied =
            !additional || http_rules::session(*additional).has_value();
        bool add = !supplied && !session.empty();
        if (add) {
          auto header = L"X-Sessionid: " + session + L"\r\n";
          if (!real_headers(request, header.c_str(), (DWORD)-1,
                            WINHTTP_ADDREQ_FLAG_ADD |
                                WINHTTP_ADDREQ_FLAG_REPLACE))
            return FALSE;
        } else if (injected &&
                   !real_headers(request, L"X-Sessionid:", (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_REPLACE) &&
                   GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND)
          return FALSE;
        {
          std::lock_guard<std::mutex> lock(state_lock);
          handles.injected(request, ticket, add);
        }
      } else if (config.content)
        observe_headers(text, length);
    }
    SetLastError(before);
    return real_send(request, text, length, data, size, total, context);
  } catch (...) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}
BOOL WINAPI close(HINTERNET handle) noexcept {
  if (!hooks_ready())
    return real_close(handle);
  try {
    DWORD before = GetLastError();
    HttpHandles::Ticket ticket;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      ticket = handles.ticket(handle);
    }
    SetLastError(before);
    BOOL result = real_close(handle);
    DWORD error = GetLastError();
    if (result) {
      std::lock_guard<std::mutex> lock(state_lock);
      handles.erase(handle, ticket);
    }
    SetLastError(error);
    return result;
  } catch (...) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}
BOOL WINAPI option(HINTERNET request, DWORD name, LPVOID data,
                   DWORD length) noexcept {
  if (!hooks_ready())
    return real_option(request, name, data, length);
  try {
    DWORD before = GetLastError();
    bool local = false;
    {
      std::lock_guard<std::mutex> lock(state_lock);
      local = handles.request(request).has_value();
    }
    DWORD filtered = 0;
    if (local && config.https && name == WINHTTP_OPTION_SECURITY_FLAGS &&
        length == sizeof(DWORD) && read(data, filtered)) {
      filtered &= ~insecure_flags;
      SetLastError(before);
      return real_option(request, name, &filtered, sizeof(filtered));
    }
    SetLastError(before);
    return real_option(request, name, data, length);
  } catch (...) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }
}
} // namespace
void observe_headers(const wchar_t *data, DWORD length) {
  // An upload of an earlier token must not overwrite a concurrent game login.
  if (image_sync_transport())
    return;
  auto text = header_text(data, length);
  if (!text)
    return;
  auto next = http_rules::session(*text);
  if (next) {
    std::lock_guard<std::mutex> lock(state_lock);
    rest_session = std::move(*next);
  }
}
std::wstring image_rest_session() {
  std::lock_guard<std::mutex> lock(state_lock);
  return rest_session;
}
void learn_cdn(const std::string &url) {
  std::string_view value(url);
  if (value.substr(0, 7) == "http://")
    value.remove_prefix(7);
  else if (value.substr(0, 8) == "https://")
    value.remove_prefix(8);
  else
    return;
  // Native CDN settings can contain a base path, query or fragment.
  // Only the validated authority participates in connection redirection.
  value = value.substr(0, value.find_first_of("/?#"));
  auto colon = value.find(':');
  if (colon != value.npos) {
    auto port = value.substr(colon + 1);
    unsigned number = 0;
    if (port.empty() || port.size() > 5)
      return;
    for (auto c : port) {
      if (c < '0' || c > '9')
        return;
      number = number * 10 + c - '0';
    }
    if (!number || number > 65535)
      return;
    value = value.substr(0, colon);
  }
  auto host = lower(widen(std::string(value)));
  if (!valid_host(host))
    return;
  std::lock_guard<std::mutex> lock(state_lock);
  if (learned < 4 && !targets.count(host)) {
    targets.insert(host);
    ++learned;
  }
}
bool install_http() {
  return stage_hook((void *)&WinHttpSetOption, (void *)&option,
                    (void **)&real_option) &&
         stage_hook((void *)&WinHttpConnect, (void *)&connect,
                    (void **)&real_connect) &&
         stage_hook((void *)&WinHttpOpenRequest, (void *)&request,
                    (void **)&real_request) &&
         stage_hook((void *)&WinHttpAddRequestHeaders, (void *)&headers,
                    (void **)&real_headers) &&
         stage_hook((void *)&WinHttpSendRequest, (void *)&send,
                    (void **)&real_send) &&
         stage_hook((void *)&WinHttpCloseHandle, (void *)&close,
                    (void **)&real_close);
}
#ifdef WWE_OWNED_TEST
extern "C"
    __declspec(dllexport) void WINAPI WweNativeTestHeaders(const wchar_t *text,
                                                           DWORD length) {
  observe_headers(text, length);
}

#endif
} // namespace wwe
