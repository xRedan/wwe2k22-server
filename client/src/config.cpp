#include "resources.hpp"
#include <stdexcept>
namespace wwe {
Config config;
namespace {
struct Reader {
  std::wstring path;
  std::wstring setting(const wchar_t *name, const wchar_t *fallback) const {
    wchar_t value[4096];
    DWORD size = GetPrivateProfileStringW(L"Server", name, fallback, value,
                                          4096, path.c_str());
    if (size >= 4095)
      throw std::invalid_argument("INI value too long");
    return std::wstring(value, size);
  }
  bool flag(const wchar_t *name, bool fallback) const {
    auto value = setting(name, fallback ? L"1" : L"0");
    if (value == L"1")
      return true;
    if (value == L"0")
      return false;
    throw std::invalid_argument("INI boolean");
  }
};
} // namespace
bool valid_host(const std::wstring &value) {
  if (value.empty() || value.size() > 253 || value == L"0.0.0.0" ||
      value == L"255.255.255.255")
    return false;
  if (value.find_first_not_of(L"0123456789.") == std::wstring::npos) {
    unsigned long parts[4]{};
    size_t index = 0, digits = 0;
    for (auto ch : value) {
      if (ch == L'.') {
        if (!digits || index >= 3)
          return false;
        index++;
        digits = 0;
      } else {
        if ((digits == 1 && parts[index] == 0) || ++digits > 3)
          return false;
        parts[index] = parts[index] * 10 + ch - L'0';
        if (parts[index] > 255)
          return false;
      }
    }
    if (index != 3 || !digits || parts[0] >= 224)
      return false;
  }
  size_t label = 0;
  wchar_t previous = 0;
  for (auto ch : value) {
    if (ch == L'.') {
      if (!label || previous == L'-')
        return false;
      label = 0;
    } else {
      if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') || (ch == L'-' && label)))
        return false;
      if (++label > 63)
        return false;
    }
    previous = ch;
  }
  return label && previous != L'-';
}
Config load_config(const std::wstring &folder) {
  Reader reader{folder + L"wwe2k22-private.ini"};
  if (GetFileAttributesW(reader.path.c_str()) == INVALID_FILE_ATTRIBUTES)
    throw std::invalid_argument("Missing INI");
  Config result;
  result.enabled = reader.flag(L"Enabled", true);
  if (!result.enabled)
    return result;
  result.host = reader.setting(L"Host", L"127.0.0.1");
  if (!valid_host(result.host))
    throw std::invalid_argument("INI host");
  for (auto &ch : result.host)
    if (ch >= L'A' && ch <= L'Z')
      ch += L'a' - L'A';
  auto port = reader.setting(L"HttpPort", L"8787");
  unsigned number = 0;
  if (port.empty() || port.size() > 5)
    throw std::invalid_argument("INI port");
  for (wchar_t c : port) {
    if (c < L'0' || c > L'9')
      throw std::invalid_argument("INI port");
    number = number * 10 + c - L'0';
  }
  if (!number || number > 65535)
    throw std::invalid_argument("INI port");
  result.port = (INTERNET_PORT)number;
  result.https = reader.flag(L"HTTPS", false);
  result.content = reader.flag(L"CustomContent", true);
  result.lobbies = reader.flag(L"PublicLobbies", true);
  result.guard = reader.flag(L"ThreadCleanupGuard", true);
  auto key_path = reader.setting(L"AccessKeyFile", L"");
  if (!key_path.empty()) {
    const bool drive = key_path.size() >= 3 &&
                       ((key_path[0] >= L'A' && key_path[0] <= L'Z') ||
                        (key_path[0] >= L'a' && key_path[0] <= L'z')) &&
                       key_path[1] == L':' &&
                       (key_path[2] == L'\\' || key_path[2] == L'/');
    // A downloaded INI must not trigger SMB authentication or device I/O.
    if (key_path.rfind(L"\\\\", 0) == 0 || key_path.rfind(L"//", 0) == 0)
      throw std::invalid_argument("Key path must be local");
    if (!drive) {
      if (key_path.find(L':') != std::wstring::npos || key_path[0] == L'\\' ||
          key_path[0] == L'/')
        throw std::invalid_argument("Ambiguous key path");
      key_path = folder + key_path;
    }
    DWORD required = GetFullPathNameW(key_path.c_str(), 0, nullptr, nullptr);
    if (!required || required > 32768)
      throw std::invalid_argument("Key path length");
    std::wstring absolute(required, L'\0');
    DWORD copied = GetFullPathNameW(key_path.c_str(), required, absolute.data(), nullptr);
    if (!copied || copied >= required)
      throw std::invalid_argument("Key path");
    absolute.resize(copied);
    if (absolute.size() < 3 || absolute[1] != L':' || absolute[2] != L'\\' ||
        GetDriveTypeW(absolute.substr(0, 3).c_str()) == DRIVE_REMOTE ||
        absolute.find(L':', 2) != std::wstring::npos)
      throw std::invalid_argument("Key path must use a local drive");
    key_path = std::move(absolute);
    KernelHandle file(CreateFileW(key_path.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
    char data[128];
    DWORD size = 0;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file.get(), &information) ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        !ReadFile(file.get(), data, sizeof(data), &size, nullptr) ||
        size >= sizeof(data))
      throw std::invalid_argument("Key file");
    std::string access(data, size);
    while (!access.empty() && (access.back() == '\r' || access.back() == '\n' ||
                               access.back() == ' '))
      access.pop_back();
    if (access.size() != 64 ||
        access.find_first_not_of("0123456789abcdef") != std::string::npos)
      throw std::invalid_argument("Key format");
    result.key_header = L"X-WWE-Lab-Key: " + widen(access) + L"\r\n";
  }
  return result;
}
} // namespace wwe
