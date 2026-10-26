#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <cstdint>
#include <string>
#include <windows.h>
#include <winhttp.h>
namespace wwe {
struct Config {
  std::wstring host = L"127.0.0.1", key_header;
  INTERNET_PORT port = 8787;
  bool enabled = true, https = false, content = true, lobbies = true,
       guard = true;
};
extern Config config;
extern volatile LONG hooks_enabled;
inline bool hooks_ready() noexcept {
  return InterlockedCompareExchange(&hooks_enabled, 0, 0) != 0;
}
Config load_config(const std::wstring &);
bool valid_host(const std::wstring &);
std::wstring module_path(HMODULE);
std::wstring directory(const std::wstring &);
bool digest_matches(const std::wstring &, const char *);
void initialize_log(const std::wstring &);
void note(const char *, int = 0) noexcept;
bool stage_hook(void *, void *, void **);
bool install_http();
bool install_game();
bool install_cleanup(uintptr_t, uintptr_t = 0);
void release_staged_cleanup() noexcept;
bool start_diagnostics(const std::wstring &) noexcept;
enum class PublicationAction { Publish, Withdraw };
bool start_publication();
void stop_publication() noexcept;
void signal_publication_stop() noexcept;
bool start_image_sync();
void stop_image_sync() noexcept;
void signal_image_sync_stop() noexcept;
bool install_image_sync(uintptr_t);
std::wstring image_rest_session();
bool image_sync_transport() noexcept;
void native_session(uint64_t);
uint64_t publication_session();
bool install_lobby_search(uintptr_t);
bool enqueue(PublicationAction, const std::string &);
bool read_memory(const void *, void *, size_t) noexcept;
template <class T> bool read(const void *p, T &value) noexcept {
  return read_memory(p, &value, sizeof(value));
}
std::string ascii(const void *, size_t);
std::wstring unicode(const void *, size_t);
std::string quote(const std::string &);
std::wstring widen(const std::string &);
void learn_cdn(const std::string &);
void observe_headers(const wchar_t *, DWORD);
void poll_lobby();
void observe_session(void *, void *);
} // namespace wwe
