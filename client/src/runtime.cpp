#include "client.hpp"
#include <algorithm>
namespace wwe {
std::wstring module_path(HMODULE module) {
  wchar_t path[32768];
  DWORD size = GetModuleFileNameW(module, path, 32768);
  if (!size || size >= 32768)
    return {};
  return std::wstring(path, size);
}
std::wstring directory(const std::wstring &path) {
  auto at = path.find_last_of(L"\\/");
  return at == std::wstring::npos ? L"" : path.substr(0, at + 1);
}
std::wstring widen(const std::string &text) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                              (int)text.size(), nullptr, 0);
  if (n <= 0)
    return {};
  std::wstring result(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                      (int)text.size(), result.data(), n);
  return result;
}
std::string quote(const std::string &text) {
  static const char hex[] = "0123456789abcdef";
  std::string result = "\"";
  for (unsigned char ch : text) {
    if (ch == '"' || ch == '\\') {
      result += '\\';
      result += (char)ch;
    } else if (ch < 32) {
      result += "\\u00";
      result += hex[ch >> 4];
      result += hex[ch & 15];
    } else
      result += (char)ch;
  }
  return result + '"';
}
bool read_memory(const void *p, void *out, size_t size) noexcept {
  SIZE_T copied = 0;
  return p && ReadProcessMemory(GetCurrentProcess(), p, out, size, &copied) &&
         copied == size;
}
// Copy readable regions in bounded chunks; never probe past a guard page.
template <class Char>
static std::basic_string<Char> bounded_text(const void *p, size_t maximum,
                                            bool printable) {
  if (!p || !maximum || maximum > 65536)
    return {};
  std::basic_string<Char> result;
  uintptr_t cursor = (uintptr_t)p;
  size_t remaining = maximum;
  while (remaining) {
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery((void *)cursor, &region, sizeof(region)) ||
        region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
      return {};
    uintptr_t end = (uintptr_t)region.BaseAddress + region.RegionSize;
    if (end <= cursor)
      return {};
    Char chunk[512];
    size_t count =
        std::min({remaining, (end - cursor) / sizeof(Char), size_t(512)});
    if (!count || !read_memory((void *)cursor, chunk, count * sizeof(Char)))
      return {};
    for (size_t i = 0; i < count; ++i) {
      auto ch = chunk[i];
      if (!ch)
        return result;
      if (printable && ((unsigned int)(unsigned char)ch < 32 ||
                        (unsigned int)(unsigned char)ch > 126))
        return {};
      result += ch;
    }
    remaining -= count;
    cursor += count * sizeof(Char);
  }
  return {};
}
std::string ascii(const void *p, size_t max) {
  return bounded_text<char>(p, max, true);
}
std::wstring unicode(const void *p, size_t max) {
  return bounded_text<wchar_t>(p, max, false);
}

} // namespace wwe

#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) void WINAPI WweNativeTestCdn(const char *url) {
  wwe::learn_cdn(wwe::ascii(url, 512));
}
#endif
