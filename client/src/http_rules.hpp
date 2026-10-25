#pragma once
#include <optional>
#include <string>
#include <string_view>
namespace wwe::http_rules {
inline wchar_t lower(wchar_t c) {
  return c >= L'A' && c <= L'Z' ? c + (L'a' - L'A') : c;
}
inline bool hex(wchar_t c, bool uppercase = false) {
  return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
         (uppercase && c >= L'A' && c <= L'F');
}
inline bool asset(std::wstring_view verb, std::wstring_view path) {
  constexpr std::wstring_view prefix = L"/ae70420fb2e24ec6a145023e0fa111f8/";
  if (verb != L"GET" || path.substr(0, prefix.size()) != prefix)
    return false;
  path.remove_prefix(prefix.size());
  if (path.size() != 44 || path[3] != L'/' || path[7] != L'/' ||
      path.substr(40) != L".bin")
    return false;
  for (size_t i = 0; i < 40; ++i)
    if (i != 3 && i != 7 && !hex(path[i]))
      return false;
  return true;
}
inline std::wstring_view trim(std::wstring_view value) {
  while (!value.empty() && (value.front() == L' ' || value.front() == L'\t'))
    value.remove_prefix(1);
  while (!value.empty() && (value.back() == L' ' || value.back() == L'\t' ||
                            value.back() == L'\r'))
    value.remove_suffix(1);
  return value;
}
// nullopt: unrelated headers. Empty string: explicit but invalid/ambiguous
// token.
inline std::optional<std::wstring> session(std::wstring_view text) {
  constexpr std::wstring_view name = L"x-sessionid";
  size_t count = 0;
  std::wstring found;
  while (!text.empty()) {
    auto end = text.find(L'\n');
    auto line = text.substr(0, end);
    if (end == text.npos)
      text = {};
    else
      text.remove_prefix(end + 1);
    auto colon = line.find(L':');
    if (colon == line.npos)
      continue;
    auto key = line.substr(0, colon);
    while (!key.empty() && (key.back() == L' ' || key.back() == L'\t'))
      key.remove_suffix(1);
    if (key.size() != name.size())
      continue;
    bool match = true;
    for (size_t i = 0; i < key.size(); ++i)
      if (lower(key[i]) != name[i]) {
        match = false;
        break;
      }
    if (!match)
      continue;
    if (++count > 1)
      return std::wstring{};
    auto token = trim(line.substr(colon + 1));
    if (token.size() == 48) {
      bool valid = true;
      for (auto c : token)
        if (!hex(c, true)) {
          valid = false;
          break;
        }
      if (valid)
        found = token;
    }
  }
  if (!count)
    return {};
  return found;
}
} // namespace wwe::http_rules
