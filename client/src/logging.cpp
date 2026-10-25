#include "resources.hpp"
#include <mutex>
namespace wwe {
namespace {
std::mutex log_mutex;
std::wstring log_path;
} // namespace
void initialize_log(const std::wstring &folder) {
  log_path = folder + L"wwe2k22-private.log";
}
void note(const char *event, int status) noexcept {
  PreserveLastError error;
  try {
    if (log_path.empty())
      return;
    std::lock_guard<std::mutex> lock(log_mutex);
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (GetFileAttributesExW(log_path.c_str(), GetFileExInfoStandard, &info) &&
        (info.nFileSizeHigh || info.nFileSizeLow >= 1024 * 1024))
      MoveFileExW(log_path.c_str(), (log_path + L".previous").c_str(),
                  MOVEFILE_REPLACE_EXISTING);
    KernelHandle file(
        CreateFileW(log_path.c_str(), FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file)
      return;
    // Fixed events only: no identities, headers, credentials or request bodies.
    std::string line = "{\"event\":" + quote(event) +
                       ",\"status\":" + std::to_string(status) + "}\r\n";
    DWORD written = 0;
    WriteFile(file.get(), line.data(), (DWORD)line.size(), &written, nullptr);
  } catch (...) {
  }
}
} // namespace wwe
