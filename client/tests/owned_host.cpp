// Owned harness: no WWE/Steam process, refuses every non-loopback send.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define DIRECTINPUT_VERSION 0x0800
#include "../src/http_state.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dinput.h>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
#include <winhttp.h>
static HMODULE mod;
static std::wstring expected;
static bool insecure_tls = false;
static thread_local bool tls_reset = false;
static thread_local DWORD request_error = 0;
static std::wstring wide(const char *p) {
  int n = MultiByteToWideChar(CP_UTF8, 0, p, -1, nullptr, 0);
  std::wstring s(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, p, -1, s.data(), n);
  s.pop_back();
  return s;
}
static bool request(HINTERNET session, const wchar_t *host, const wchar_t *path,
                    const wchar_t *headers = nullptr, bool allow_http = false) {
  auto c = WinHttpConnect(session, host, 443, 0);
  if (!c)
    return false;
  auto r = WinHttpOpenRequest(c, L"GET", path, nullptr, nullptr,
                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                              allow_http ? 0 : WINHTTP_FLAG_SECURE);
  if (!r) {
    WinHttpCloseHandle(c);
    return false;
  }
  DWORD n = 0;
  WinHttpQueryOption(r, WINHTTP_OPTION_URL, nullptr, &n);
  std::wstring url(n / 2, L'\0');
  bool ok = WinHttpQueryOption(r, WINHTTP_OPTION_URL, url.data(), &n) &&
            url.rfind(expected, 0) == 0;
  if (ok && insecure_tls) {
    DWORD ignore = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(r, WINHTTP_OPTION_SECURITY_FLAGS, &ignore, sizeof(ignore));
  }
  if (ok)
    ok = WinHttpSendRequest(r, headers, headers ? (DWORD)-1 : 0, nullptr, 0, 0,
                            0) &&
         WinHttpReceiveResponse(r, nullptr);
  request_error = GetLastError();
  if (insecure_tls) {
    DWORD flags = 0, len = sizeof(flags);
    tls_reset =
        WinHttpQueryOption(r, WINHTTP_OPTION_SECURITY_FLAGS, &flags, &len) &&
        !(flags & (SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE));
  }
  DWORD status = 0;
  n = sizeof(status);
  if (ok)
    ok = WinHttpQueryHeaders(
             r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr,
             &status, &n, nullptr) &&
         status == 200;
  WinHttpCloseHandle(r);
  WinHttpCloseHandle(c);
  return ok;
}
using Cdn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                         const char *);
__declspec(noinline) uint64_t cdn_fixture(uint64_t a, uint64_t b, uint64_t c,
                                          uint64_t d, uint64_t e, uint64_t f,
                                          uint64_t g, uint64_t h, uint64_t i,
                                          uint64_t j, const char *url) {
  volatile uint64_t total = a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g +
                            8 * h + 9 * i + 10 * j;
  return total + (unsigned char)url[0];
}
static uint64_t lobby = (uint64_t(0x01840000) << 32) | 1234,
                owner_id = 76561198000000001ULL;
static int type_value = 2;
static bool joinable = true;
static void *manager = nullptr;
__declspec(noinline) bool set_type(void *, uint64_t id, int value) {
  if (id != lobby)
    return false;
  type_value = value;
  return true;
}
__declspec(noinline) bool set_joinable(void *, uint64_t id, bool value) {
  if (id != lobby)
    return false;
  joinable = value;
  return true;
}
__declspec(noinline) void *owner(void *, uint64_t *out, uint64_t id) {
  *out = id == lobby ? owner_id : 0;
  return out;
}
__declspec(noinline) int count(void *, uint64_t id) {
  return id == lobby ? 3 : 0;
}
__declspec(noinline) int members(void *, uint64_t id) {
  return id == lobby ? 1 : 0;
}
__declspec(noinline) int limit(void *, uint64_t id) {
  return id == lobby ? 2 : 0;
}
__declspec(noinline) bool item(void *, uint64_t id, int i, char *key, int kn,
                               char *value, int vn) {
  if (id != lobby || i < 0 || i >= 3)
    return false;
  const char *keys[] = {"spec_vc_matchid", "spec_hostID", "spec_pubOpen"};
  std::string values[] = {"111", std::to_string(owner_id), "1"};
  if ((int)strlen(keys[i]) + 1 > kn || (int)values[i].size() + 1 > vn)
    return false;
  strcpy(key, keys[i]);
  strcpy(value, values[i].c_str());
  return true;
}
__declspec(noinline) void *reader(void *object, void *result) {
  *(uint32_t *)result = 0x8a46d950;
  *(void **)((char *)object + 0xa8) = nullptr;
  *(uint64_t *)((char *)object + 0xe8) = 111;
  return result;
}
__declspec(noinline) bool unexpected_type(void *, uint64_t id, int type) {
  volatile uint64_t value = id + type;
  return value == 0;
}
static int steam_fixture(bool rebind = false, bool unexpected = false) {
  auto arena = (unsigned char *)VirtualAlloc(
      nullptr, 0x4000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!arena)
    return 61;
  std::vector<unsigned char> memory(0x6100);
  manager = memory.data();
  memcpy(arena + 0x36e5210, &manager, 8);
  *(uint64_t *)(arena + 0x34a3878) = 111;
  *(uint64_t *)((char *)manager + 0x6088) = lobby;
  *(uint32_t *)((char *)manager + 0x6090) = 1;
  *(uint64_t *)((char *)manager + 0x5f80) = owner_id;
  void *table[36]{};
  table[0x118 / 8] = (void *)&owner;
  table[0xa8 / 8] = (void *)&count;
  table[0xb0 / 8] = (void *)&item;
  table[0x88 / 8] = (void *)&members;
  table[0x100 / 8] = (void *)&limit;
  table[0x108 / 8] = (void *)&set_type;
  table[0x110 / 8] = (void *)&set_joinable;
  void **instance = table;
  auto bind =
      (int(WINAPI *)(void *, void *))GetProcAddress(mod, "WweNativeTestBind");
  auto poll = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestPoll");
  auto observe = (void *(WINAPI *)(void *, void *, void *))GetProcAddress(
      mod, "WweNativeTestReader");
  if (!bind || !poll || !observe || !bind(arena, &instance))
    return 62;
  unsigned char response[0x100]{};
  uint32_t result = 0;
  if (observe((void *)&reader, response, &result) != &result ||
      result != 0x8a46d950)
    return 63;
  int s1 = poll();
  Sleep(350);
  volatile auto jf = &set_joinable;
  volatile auto tf = &set_type;
  jf(&instance, lobby, false);
  Sleep(350);
  jf(&instance, lobby, true);
  int s2 = poll();
  Sleep(350);
  *(uint8_t *)((char *)manager + 0x5f60) = 1;
  tf(&instance, lobby, 0);
  Sleep(350);
  int s3 = poll();
  Sleep(150);
  if (type_value != 0 || !joinable)
    return 64;
  *(uint8_t *)((char *)manager + 0x5f60) = 0;
  int state = poll();
  if (s1 != 5 || s2 != 5 || s3 != 6)
    return 67;
  if (state != 5) {
    printf("{\"steam_state\":%d}\n", state);
    return 65;
  }
  Sleep(350);
  void *replacement_table[36];
  memcpy(replacement_table, table, sizeof(table));
  if (unexpected)
    replacement_table[0x108 / 8] = (void *)&unexpected_type;
  void **replacement = replacement_table;
  if (rebind) {
    bool accepted = bind(arena, &replacement) != 0;
    if (accepted == unexpected)
      return 123;
    poll();
    Sleep(350);
  }
  *(uint32_t *)((char *)manager + 0x6090) = 0;
  poll();
  auto drain = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestDrain");
  if (!drain || !drain())
    return 66;
  // Game memory stays mapped until process shutdown, like the actual module.
  return 0;
}
static void *query_task = nullptr;
static int query_resets = 0, query_errors = 0;
static uint64_t query_field_data[3] = {1, 101, 0};
static std::vector<uint64_t> query_candidates;
static void query_reset(void *p) {
  if (p != (char *)query_task + 0x60)
    abort();
  ++query_resets;
  query_candidates.clear();
}
static uint64_t query_append(void *p, const void *candidate, uint64_t,
                             uint64_t) {
  if (p != (char *)query_task + 0xa0)
    abort();
  const auto data = (const unsigned char *)candidate;
  for (size_t i = 0x14; i < 0x3c; ++i)
    if (data[i] != 0xff)
      abort();
  for (size_t i = 8; i < 0x14; ++i)
    if (data[i])
      abort();
  for (size_t i = 0x3c; i < 0x44; ++i)
    if (data[i])
      abort();
  uint64_t id = 0;
  memcpy(&id, data, 8);
  query_candidates.push_back(id);
  ++*(uint32_t *)((char *)query_task + 0xac);
  return 1;
}
static void *query_value(void *, uint32_t key, uint32_t type) {
  return key == 7 && type == 1 ? query_field_data : nullptr;
}
static void query_error(void *, uint32_t operation, uint32_t error, uint32_t) {
  if (operation != 44 || error != 0x10000010)
    abort();
  ++query_errors;
}
static uint64_t query_original(void *) { return 77; }
static int query_fixture(const std::string &mode) {
  auto invoke =
      (uint64_t(WINAPI *)(void *, void *, void *, void *, void *,
                          void *))GetProcAddress(mod, "WweNativeTestSearch");
  auto identity =
      (void(WINAPI *)(uint64_t))GetProcAddress(mod, "WweNativeTestSession");
  if (!invoke || !identity)
    return 140;
  unsigned char task[0x118]{}, input[0x90]{}, manager_data[0x6100]{},
      filters[0x18]{};
  query_task = task;
  *(uint32_t *)(task + 8) = 4;
  *(void **)(task + 0x38) = input;
  *(void **)(task + 0x30) = manager_data;
  *(uint32_t *)(task + 0xc) = 44;
  *(uint32_t *)(task + 0x90) = 9;
  *(uint32_t *)(task + 0xac) = 5;
  *(uint32_t *)(input + 0x64) = 1;
  *(void **)(input + 0x68) = filters;
  *(int32_t *)(input + 0x88) = 2;
  *(int32_t *)(manager_data + 0x6094) = 60;
  *(uint32_t *)(filters + 8) = 7;
  *(uint32_t *)(filters + 12) = 1;
  *(uint32_t *)(filters + 16) = 4;
  int code = std::stoi(mode.substr(6));
  if (code == 116)
    *(uint32_t *)(task + 8) = 5;
  auto active = (void(WINAPI *)(int))GetProcAddress(mod, "WweNativeTestActive");
  if (code == 117)
    active(0);
  query_field_data[1] = (uint64_t)code;
  if (code != 113)
    identity(111);
  if (code == 114)
    *(uint32_t *)(input + 0x64) = 29;
  if (code == 115)
    *(void **)(input + 0x68) = (void *)1;
  std::thread change;
  if (code == 112)
    change = std::thread([=] {
      Sleep(100);
      identity(222);
    });
  auto result = invoke(task, (void *)&query_reset, (void *)&query_append,
                       (void *)&query_value, (void *)&query_error,
                       (void *)&query_original);
  if (change.joinable())
    change.join();
  if (code == 117)
    active(1);
  if (code >= 116) {
    return result == 77 && query_errors == 0 && query_resets == 0 &&
                   *(uint32_t *)(task + 0x90) == 9
               ? 0
               : 146;
  }
  bool success = code == 101 || code == 102;
  if (result != (success ? 1U : 0U) || query_errors != (success ? 0 : 1) ||
      query_resets != (success ? 1 : 0))
    return 141;
  if (success) {
    if (*(uint32_t *)(task + 0x90) != 2 ||
        *(uint32_t *)(task + 0xac) != query_candidates.size())
      return 142;
    if (code == 101 && (query_candidates.size() != 2 ||
                        query_candidates[0] != 109212290963898369ULL ||
                        query_candidates[1] != 109212290963898370ULL))
      return 143;
    if (code == 102 && !query_candidates.empty())
      return 144;
  } else if (*(uint32_t *)(task + 0x90) != 9 || *(uint32_t *)(task + 0xac) != 5)
    return 145;
  return 0;
}
static int guard_fixture() {
  auto arena = (unsigned char *)VirtualAlloc(
      nullptr, 0x4000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!arena)
    return 71;
  auto entry = arena + 0x2329060;
  unsigned char prologue[] = {
      0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x8b, 0x0d, 0,    0,    0, 0, 0x65,
      0x48, 0x8b, 0x04, 0x25, 0x58, 0,    0,    0,    0xba, 0x38, 1, 0, 0};
  int32_t disp = (int32_t)((arena + 0x3529e98) - (entry + 12));
  memcpy(prologue + 8, &disp, 4);
  memcpy(entry, prologue, sizeof(prologue));
  std::vector<unsigned char> tail = {0x48, 0xb8};
  uintptr_t counter = (uintptr_t)(arena + 0x1000);
  for (int i = 0; i < 8; ++i)
    tail.push_back((unsigned char)(counter >> (8 * i)));
  unsigned char epilogue[] = {0xff, 0, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
  tail.insert(tail.end(), epilogue, epilogue + sizeof(epilogue));
  memcpy(entry + 26, tail.data(), tail.size());
  DWORD old = 0;
  if (!VirtualProtect(entry, 64, PAGE_EXECUTE_READ, &old))
    return 72;
  FlushInstructionCache(GetCurrentProcess(), entry, 64);
  unsigned char slot[0x140]{};
  void *slots[1] = {slot};
  void *directory = slots;
  auto install =
      (int(WINAPI *)(void *, void *))GetProcAddress(mod, "WweNativeTestGuard");
  if (!install || !install(arena, &directory))
    return 73;
  volatile auto call = (void (*)())entry;
  auto calls = (uint32_t *)counter;
  call();
  if (*calls != 0)
    return 74;
  *(void **)(arena + 0x356afb0) = slot;
  call();
  if (*calls != 1)
    return 75;
  *(void **)(arena + 0x356afb0) = nullptr;
  *(void **)(slot + 0x138) = slot;
  call();
  if (*calls != 2)
    return 76;
  *(void **)(slot + 0x138) = nullptr;
  directory = nullptr;
  call();
  if (*calls != 3)
    return 77;
  directory = slots;
  slots[0] = nullptr;
  call();
  if (*calls != 4)
    return 78;
  auto active = (void(WINAPI *)(int))GetProcAddress(mod, "WweNativeTestActive");
  if (!active)
    return 124;
  slots[0] = slot;
  active(0);
  call();
  active(1);
  if (*calls != 5)
    return 125;
  call();
  if (*calls != 5)
    return 126;
  return 0;
}
__declspec(noinline) double cdn_float_fixture(uint64_t a, double b, uint64_t c,
                                              double d, uint64_t e, uint64_t f,
                                              uint64_t g, uint64_t h,
                                              uint64_t i, uint64_t j,
                                              const char *url) {
  volatile double total = a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g +
                          8 * h + 9 * i + 10 * j;
  return total + (unsigned char)url[0];
}
static int edge_fixture(HINTERNET session) {
  auto remember = (void(WINAPI *)(const wchar_t *, DWORD))GetProcAddress(
      mod, "WweNativeTestHeaders");
  auto learn =
      (void(WINAPI *)(const char *))GetProcAddress(mod, "WweNativeTestCdn");
  if (!remember || !learn)
    return 81;
  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  auto bytes = (char *)VirtualAlloc(nullptr, si.dwPageSize * 2,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!bytes)
    return 82;
  DWORD old = 0;
  VirtualProtect(bytes + si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &old);
  const char *url = "http://boundary.fixture.invalid/";
  size_t len = strlen(url) + 1;
  char *end = bytes + si.dwPageSize - len;
  memcpy(end, url, len);
  learn(end);
  learn((const char *)1);
  if (!request(session, L"boundary.fixture.invalid", L"/boundary"))
    return 83;
  const wchar_t *asset = L"/ae70420fb2e24ec6a145023e0fa111f8/abc/def/"
                         L"0123456789abcdef0123456789abcdef.bin";
  std::wstring header =
      L"X-Sessionid: cccccccccccccccccccccccccccccccccccccccccccccccc\r\n";
  size_t length = header.size();
  auto text = (wchar_t *)(bytes + si.dwPageSize - length * sizeof(wchar_t));
  memcpy(text, header.data(), length * sizeof(wchar_t));
  remember(text, (DWORD)length);
  if (!request(session, L"boundary.fixture.invalid", asset))
    return 84;
  remember((const wchar_t *)1, 30);
  remember(L"Content-Type: text/plain\r\n", (DWORD)-1);
  remember(L"X-Sessionid: invalid", 8193);
  if (!request(session, L"boundary.fixture.invalid", asset))
    return 85;
  remember(L"X-Sessionid: invalid\r\n", (DWORD)-1);
  if (!request(session, L"boundary.fixture.invalid", asset))
    return 86;
  // A NUL beyond a guard page is never read.
  memset(end, 'x', len);
  learn(end);
  VirtualFree(bytes, 0, MEM_RELEASE);
  return 0;
}
static int queue_fixture(HINTERNET session) {
  auto set =
      (void(WINAPI *)(uint64_t))GetProcAddress(mod, "WweNativeTestSession");
  auto put = (int(WINAPI *)(const char *, const char *))GetProcAddress(
      mod, "WweNativeTestQueue");
  auto drain = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestDrain");
  if (!set || !put || !drain)
    return 91;
  if (put("publish", "{}"))
    return 92;
  set(111);
  if (put("invalid", "{}") || put("publish", "") ||
      put("publish", std::string(65537, 'x').c_str()))
    return 93;
  if (!put("publish", "{\"block\":true}") ||
      !request(session, L"wwe2k22-peg.2ksports.com", L"/barrier"))
    return 94;
  int accepted = 0;
  for (int i = 0; i < 40; ++i)
    accepted += put("publish", "{\"stale\":true}");
  if (accepted != 16)
    return 95;
  set(222);
  if (!put("publish", "{\"after\":true}") ||
      !request(session, L"wwe2k22-peg.2ksports.com", L"/release") || !drain())
    return 96;
  return 0;
}
static int publication_fixture(HINTERNET session, const std::string &mode) {
  auto set =
      (void(WINAPI *)(uint64_t))GetProcAddress(mod, "WweNativeTestSession");
  auto put = (int(WINAPI *)(const char *, const char *))GetProcAddress(
      mod, "WweNativeTestQueue");
  auto drain = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestDrain");
  auto active = (void(WINAPI *)(int))GetProcAddress(mod, "WweNativeTestActive");
  if (!set || !put || !drain || !active)
    return 141;
  set(111);
  if (mode == "publication-pending" || mode == "publication-rotate") {
    if (!put("publish", "{\"publication_case\":\"pending\"}") ||
        !request(session, L"wwe2k22-peg.2ksports.com", L"/barrier"))
      return 142;
    bool rotate = mode == "publication-rotate";
    if (rotate)
      set(222);
    if (!put(rotate ? "publish" : "withdraw", "{\"newer\":true}") ||
        !request(session, L"wwe2k22-peg.2ksports.com", L"/release") || !drain())
      return 143;
  } else {
    auto name = mode.substr(std::string("publication-").size());
    auto body = "{\"publication_case\":\"" + name + "\"}";
    // The publisher must refuse redirects independently of general HTTP hooks.
    if (name == "redirect")
      active(0);
    bool ok = put("publish", body.c_str()) && drain();
    if (name == "redirect")
      active(1);
    if (!ok)
      return 144;
  }
  return 0;
}
static LONG CALLBACK fixture_exception(EXCEPTION_POINTERS *p) {
  return p->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION
             ? EXCEPTION_CONTINUE_EXECUTION
             : EXCEPTION_CONTINUE_SEARCH;
}
static bool loopback_url(HINTERNET request) {
  DWORD bytes = 0;
  WinHttpQueryOption(request, WINHTTP_OPTION_URL, nullptr, &bytes);
  std::wstring url(bytes / 2, L'\0');
  return WinHttpQueryOption(request, WINHTTP_OPTION_URL, url.data(), &bytes) &&
         url.rfind(expected, 0) == 0;
}
static bool finish(HINTERNET request, DWORD expected_status = 200) {
  if (!loopback_url(request) ||
      !WinHttpSendRequest(request, nullptr, 0, nullptr, 0, 0, 0) ||
      !WinHttpReceiveResponse(request, nullptr))
    return false;
  DWORD status = 0, bytes = sizeof(status);
  if (!WinHttpQueryHeaders(
          request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
          nullptr, &status, &bytes, nullptr) ||
      status != expected_status)
    return false;
  char buffer[64];
  DWORD count = 0;
  do {
    if (!WinHttpReadData(request, buffer, sizeof(buffer), &count))
      return false;
  } while (count);
  return true;
}
static int child_fixture(HINTERNET independent) {
  HINTERNET session = WinHttpOpen(
      L"child-fixture", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
  if (!session)
    return 101;
  WinHttpSetTimeouts(session, 2000, 2000, 2000, 2000);
  auto connection =
      WinHttpConnect(session, L"wwe2k22-peg.2ksports.com", 443, 0);
  if (!connection)
    return 102;
  auto request = WinHttpOpenRequest(
      connection, L"GET", L"/child-after-parent-close", nullptr, nullptr,
      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!request || !loopback_url(request))
    return 103;
  if (!WinHttpCloseHandle(connection) || !WinHttpCloseHandle(session) ||
      finish(request))
    return 104;
  WinHttpCloseHandle(request);
  if (!::request(independent, L"wwe2k22-peg.2ksports.com",
                 L"/independent-after-close"))
    return 122;
  return 0;
}
static int retry_fixture(HINTERNET session) {
  auto remember = (void(WINAPI *)(const wchar_t *, DWORD))GetProcAddress(
      mod, "WweNativeTestHeaders");
  if (!remember)
    return 105;
  remember(L"X-Sessionid: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
           (DWORD)-1);
  auto c = WinHttpConnect(session, L"wwe2k22-peg.2ksports.com", 443, 0);
  auto r = WinHttpOpenRequest(c, L"GET",
                              L"/ae70420fb2e24ec6a145023e0fa111f8/abc/def/"
                              L"0123456789abcdef0123456789abcdef.bin",
                              nullptr, nullptr, WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
  if (!r || !finish(r))
    return 106;
  remember(L"X-Sessionid: invalid\r\n", (DWORD)-1);
  if (!finish(r))
    return 107;
  // A header supplied by the game belongs to the game and must remain usable.
  if (!WinHttpAddRequestHeaders(
          r,
          L"X-Sessionid: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n",
          (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) ||
      !finish(r))
    return 108;
  WinHttpCloseHandle(r);
  WinHttpCloseHandle(c);
  return 0;
}
static int handle_generation_fixture() {
  wwe::HttpHandles h(1, 1);
  void *one = (void *)uintptr_t(1);
  void *two = (void *)uintptr_t(2);
  if (!h.remember_connection(one, true))
    return 109;
  auto connection = h.ticket(one);
  if (!h.remember_request(one, true, false))
    return 110;
  h.erase(one, connection);
  if (!h.request(one).has_value())
    return 111;
  auto stale = h.ticket(one);
  if (!h.remember_request(one, true, true))
    return 112;
  h.erase(one, stale);
  auto current = h.ticket(one);
  h.injected(one, current, true);
  h.injected(one, stale, false);
  if (!h.request(one).value_or(false) || !h.injected(one) ||
      h.remember_request(two, true, false))
    return 113;
  h.remember_request(one, false, false);
  if (h.request(one))
    return 114;
  return 0;
}
static int incomplete_session_fixture() {
  auto set =
      (void(WINAPI *)(uint64_t))GetProcAddress(mod, "WweNativeTestSession");
  auto observe = (void(WINAPI *)(void *, void *))GetProcAddress(
      mod, "WweNativeTestObserveSession");
  auto poll = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestPoll");
  auto queue = (int(WINAPI *)(const char *, const char *))GetProcAddress(
      mod, "WweNativeTestQueue");
  auto drain = (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestDrain");
  if (!set || !observe || !poll || !queue || !drain)
    return 115;
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  auto memory = (char *)VirtualAlloc(nullptr, info.dwPageSize * 2,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!memory)
    return 116;
  auto object = memory + info.dwPageSize - 0xc0;
  *(uint64_t *)(object + 0xe8) = 222;
  DWORD old = 0;
  VirtualProtect(memory, info.dwPageSize, PAGE_NOACCESS, &old);
  uint32_t status = 0x8a46d950;
  set(111);
  observe(object, &status);
  poll();
  if (!queue("publish", "{\"commit_checked\":true}") || !drain())
    return 117;
  VirtualFree(memory, 0, MEM_RELEASE);
  return 0;
}
static int redirect_fixture(HINTERNET session) {
  auto c = WinHttpConnect(session, L"wwe2k22-peg.2ksports.com", 443, 0);
  auto r =
      WinHttpOpenRequest(c, L"GET", L"/redirect", nullptr, nullptr,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!r || !finish(r, 302))
    return 118;
  WinHttpCloseHandle(r);
  WinHttpCloseHandle(c);
  return 0;
}
static int concurrent_fixture() {
  std::atomic<bool> valid{true};
  std::vector<std::thread> threads;
  for (int i = 0; i < 8; ++i)
    threads.emplace_back([&] {
      auto session =
          WinHttpOpen(L"concurrent-fixture", WINHTTP_ACCESS_TYPE_NO_PROXY,
                      nullptr, nullptr, 0);
      if (!session) {
        valid = false;
        return;
      }
      WinHttpSetTimeouts(session, 2000, 2000, 2000, 2000);
      for (int j = 0; j < 3; ++j)
        if (!request(session, L"wwe2k22-peg.2ksports.com", L"/parallel"))
          valid = false;
      WinHttpCloseHandle(session);
    });
  for (auto &t : threads)
    t.join();
  return valid ? 0 : 119;
}
int main(int argc, char **argv) {
  if (argc < 3)
    return 10;
  expected = wide(argv[1]);
  std::string mode = argv[2];
  mod = GetModuleHandleW(L"dinput8.dll");
  if (!mod)
    return 11;
  void *input = nullptr;
  HRESULT hr = DirectInput8Create(GetModuleHandleW(nullptr), 0x800,
                                  IID_IDirectInput8W, &input, nullptr);
  if (input)
    ((IUnknown *)input)->Release();
  if (hr != S_OK)
    return 12;
  if (mode == "startup-fail")
    SetEnvironmentVariableW(L"WWE_OWNED_FAIL_START", L"1");
  if (mode == "activation-fail")
    SetEnvironmentVariableW(L"WWE_OWNED_FAIL_AFTER_APPLY", L"1");
  HINTERNET s = WinHttpOpen(L"native-owned-fixture",
                            WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
  if (!s) {
    if (mode == "startup-fail" || mode == "activation-fail") {
      auto stopped =
          (int(WINAPI *)())GetProcAddress(mod, "WweNativeTestWorkerStopped");
      if (!stopped || !stopped())
        return 127;
      auto raw_open = (decltype(&WinHttpOpen))GetProcAddress(
          GetModuleHandleW(L"winhttp.dll"), "WinHttpOpen");
      auto raw = raw_open(L"inert-fixture", WINHTTP_ACCESS_TYPE_NO_PROXY,
                          nullptr, nullptr, 0);
      if (!raw)
        return 128;
      auto conn = WinHttpConnect(raw, L"wwe2k22-peg.2ksports.com", 443, 0);
      auto req =
          WinHttpOpenRequest(conn, L"GET", L"/never-send", nullptr, nullptr,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
      DWORD bytes = 0;
      WinHttpQueryOption(req, WINHTTP_OPTION_URL, nullptr, &bytes);
      std::wstring url(bytes / 2, L'\0');
      if (!WinHttpQueryOption(req, WINHTTP_OPTION_URL, url.data(), &bytes) ||
          url.rfind(L"https://wwe2k22-peg.2ksports.com/", 0) != 0)
        return 129;
      WinHttpCloseHandle(req);
      WinHttpCloseHandle(conn);
      WinHttpCloseHandle(raw);
    }
    puts("{\"open_blocked\":true}");
    return 20;
  }
  WinHttpSetTimeouts(s, 2000, 2000, 2000, 2000);
  if (GetModuleHandleW(L"wwe2k22-gadget.dll"))
    return 13;
  if (mode == "tls" || mode == "tls-default") {
    insecure_tls = mode == "tls";
    bool accepted = request(s, L"wwe2k22-peg.2ksports.com", L"/health");
    if (accepted || (insecure_tls && !tls_reset) ||
        request_error != ERROR_WINHTTP_SECURE_FAILURE) {
      printf("{\"tls_accepted\":%d,\"tls_reset\":%d,\"error\":%lu}\n", accepted,
             tls_reset, request_error);
      return 41;
    }
    puts("{\"tls_certificate_rejected\":true,\"insecure_flags_reset\":true}");
    return 0;
  }
  if (mode == "unrelated") {
    bool result = request(s, L"example.invalid", L"/health");
    printf("{\"unrelated_blocked\":%s}\n", result ? "false" : "true");
    return result ? 21 : 0;
  }
  if (!request(s, L"508223012e5a5ff19f30a391b2bdadc0.my.2k.com", L"/health"))
    return 22;
  if (mode == "children") {
    int code = child_fixture(s);
    if (code)
      return code;
  }
  if (mode == "retry") {
    int code = retry_fixture(s);
    if (code)
      return code;
  }
  if (mode == "generation") {
    int code = handle_generation_fixture();
    if (code)
      return code;
  }
  if (mode == "commit") {
    int code = incomplete_session_fixture();
    if (code)
      return code;
  }
  if (mode == "redirect") {
    int code = redirect_fixture(s);
    if (code)
      return code;
  }
  if (mode == "concurrent") {
    int code = concurrent_fixture();
    if (code)
      return code;
  }
  if (mode == "asset-inline") {
    auto remember = (void(WINAPI *)(const wchar_t *, DWORD))GetProcAddress(
        mod, "WweNativeTestHeaders");
    if (!remember)
      return 120;
    remember(
        L"X-Sessionid: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
        (DWORD)-1);
    if (!request(s, L"wwe2k22-peg.2ksports.com",
                 L"/ae70420fb2e24ec6a145023e0fa111f8/abc/def/"
                 L"0123456789abcdef0123456789abcdef.bin",
                 L"X-Sessionid: "
                 L"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"))
      return 121;
  }
  if (mode == "cdn") {
    auto install =
        (int(WINAPI *)(void *))GetProcAddress(mod, "WweNativeTestGateway");
    if (!install || !install((void *)&cdn_fixture))
      return 30;
    Cdn fn = &cdn_fixture;
    volatile uint64_t result =
        fn(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, "http://cdn.fixture.invalid/");
    if (result != 489)
      return 31;
    const wchar_t *asset = L"/ae70420fb2e24ec6a145023e0fa111f8/abc/def/"
                           L"0123456789abcdef0123456789abcdef.bin";
    if (!request(s, L"wwe2k22-peg.2ksports.com", L"/remember",
                 L"X-Sessionid: "
                 L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"))
      return 32;
    if (!request(s, L"cdn.fixture.invalid", asset))
      return 33;
    if (!request(s, L"cdn.fixture.invalid", L"/not-asset"))
      return 34;
    if (!request(
            s, L"wwe2k22-peg.2ksports.com", L"/ambiguous",
            L"X-Sessionid: "
            L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nX-Sessionid: "
            L"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"))
      return 35;
    if (!request(s, L"cdn.fixture.invalid", asset))
      return 36;
  }
  if (mode == "steam" || mode == "steam-rebind" || mode == "steam-unexpected") {
    int code = steam_fixture(mode != "steam", mode == "steam-unexpected");
    if (code)
      return code;
  }
  if (mode.rfind("query-", 0) == 0) {
    int code = query_fixture(mode);
    if (code)
      return code;
  }
  if (mode == "guard") {
    int code = guard_fixture();
    if (code)
      return code;
  }
  if (mode == "exception") {
    auto handler = AddVectoredExceptionHandler(0, fixture_exception);
    if (!handler)
      return 87;
    for (int i = 0; i < 40; ++i)
      RaiseException(EXCEPTION_ILLEGAL_INSTRUCTION, 0, 0, nullptr);
    RemoveVectoredExceptionHandler(handler);
  }
  if (mode == "edges") {
    int code = edge_fixture(s);
    if (code)
      return code;
  }
  if (mode.rfind("publication-", 0) == 0) {
    int code = publication_fixture(s, mode);
    if (code)
      return code;
  }
  if (mode == "queue") {
    int code = queue_fixture(s);
    if (code)
      return code;
  }
  if (mode == "cdn-floats") {
    auto install =
        (int(WINAPI *)(void *))GetProcAddress(mod, "WweNativeTestGateway");
    if (!install || !install((void *)&cdn_float_fixture))
      return 37;
    volatile auto fn = &cdn_float_fixture;
    double result = fn(1, 2.25, 3, 4.5, 5, 6, 7, 8, 9, 10,
                       "http://floating.fixture.invalid/");
    if (result != 491.5 || !request(s, L"floating.fixture.invalid", L"/float"))
      return 38;
  }
  WinHttpCloseHandle(s);
  puts("{\"native\":true,\"passed\":true,\"gadget_loaded\":false}");
  return 0;
}
