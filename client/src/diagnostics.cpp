#include "resources.hpp"
#include <cstring>
namespace wwe {
namespace {
HANDLE diagnostic_file = INVALID_HANDLE_VALUE;
uintptr_t image_base = 0, image_size = 0;
volatile LONG diagnostic_budget = 16;
// Sanitizer-internal probes can enter this handler. Instrumenting the fault
// path would recursively fault before the original exception can be handled.
#if defined(__clang__)
__attribute__((no_sanitize("address", "undefined", "thread")))
#endif
char *number(char *out, uint64_t value) noexcept {
  char reverse[24];
  unsigned n = 0;
  do {
    reverse[n++] = (char)('0' + value % 10);
    value /= 10;
  } while (value);
  while (n)
    *out++ = reverse[--n];
  return out;
}
#if defined(__clang__)
__attribute__((no_sanitize("address", "undefined", "thread")))
#endif
LONG CALLBACK observe_exception(EXCEPTION_POINTERS *exception) noexcept {
  if (!exception || !exception->ExceptionRecord || !exception->ContextRecord ||
      diagnostic_file == INVALID_HANDLE_VALUE)
    return EXCEPTION_CONTINUE_SEARCH;
  DWORD code = exception->ExceptionRecord->ExceptionCode;
  if (code != EXCEPTION_ACCESS_VIOLATION &&
      code != EXCEPTION_ILLEGAL_INSTRUCTION)
    return EXCEPTION_CONTINUE_SEARCH;
  LONG remaining = InterlockedCompareExchange(&diagnostic_budget, 0, 0);
  for (;;) {
    if (remaining <= 0)
      return EXCEPTION_CONTINUE_SEARCH;
    LONG previous = InterlockedCompareExchange(&diagnostic_budget,
                                               remaining - 1, remaining);
    if (previous == remaining)
      break;
    remaining = previous;
  }
  PreserveLastError error;
  // No heap allocations, locks, stack walking or raw addresses in the handler.
  char line[128];
  char *p = line;
  const char prefix[] = "{\"event\":\"native-exception\",\"code\":";
  memcpy(p, prefix, sizeof(prefix) - 1);
  p += sizeof(prefix) - 1;
  p = number(p, code);
  const char middle[] = ",\"game_rva\":";
  memcpy(p, middle, sizeof(middle) - 1);
  p += sizeof(middle) - 1;
  uintptr_t ip = (uintptr_t)exception->ContextRecord->Rip;
  p = number(p, ip >= image_base && ip - image_base < image_size
                    ? ip - image_base
                    : 0);
  *p++ = '}';
  *p++ = '\r';
  *p++ = '\n';
  DWORD written = 0;
  WriteFile(diagnostic_file, line, (DWORD)(p - line), &written, nullptr);
  return EXCEPTION_CONTINUE_SEARCH;
}
} // namespace
bool start_diagnostics(const std::wstring &folder) noexcept {
  try {
    image_base = (uintptr_t)GetModuleHandleW(nullptr);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!read((void *)image_base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !read((void *)(image_base + dos.e_lfanew), nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE)
      return false;
    image_size = nt.OptionalHeader.SizeOfImage;
    auto path = folder + L"wwe2k22-native-crash.log";
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) &&
        (data.nFileSizeHigh || data.nFileSizeLow >= 1024 * 1024))
      MoveFileExW(path.c_str(), (path + L".previous").c_str(),
                  MOVEFILE_REPLACE_EXISTING);
    diagnostic_file =
        CreateFileW(path.c_str(), FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (diagnostic_file == INVALID_HANDLE_VALUE)
      return false;
    if (!AddVectoredExceptionHandler(1, observe_exception)) {
      CloseHandle(diagnostic_file);
      diagnostic_file = INVALID_HANDLE_VALUE;
      return false;
    }
    return true;
  } catch (...) {
    return false;
  }
}
} // namespace wwe
