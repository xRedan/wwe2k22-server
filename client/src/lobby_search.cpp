// Server-scoped discovery; Steam still retrieves metadata, pings and joins.
#include "profile.hpp"
#include "resources.hpp"
#include <array>
#include <cstring>
#include <vector>
namespace wwe {
namespace {
using Start = uint64_t (*)(void *);
using Reset = void (*)(void *);
using Append = uint64_t (*)(void *, const void *, uint64_t, uint64_t);
using FieldValue = void *(*)(void *, uint32_t, uint32_t);
using Error = void (*)(void *, uint32_t, uint32_t, uint32_t);
Start original_start = nullptr;
Reset reset_results = nullptr;
Append append_candidate = nullptr;
FieldValue filter_value = nullptr;
Error report_error = nullptr;
template <class T> bool get(uintptr_t p, T &value) {
  return read((void *)p, value);
}
bool writable(void *p, size_t length) {
  MEMORY_BASIC_INFORMATION m{};
  if (!p || !VirtualQuery(p, &m, sizeof(m)) || m.State != MEM_COMMIT ||
      (m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
      !(m.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                     PAGE_EXECUTE_WRITECOPY)))
    return false;
  auto offset = (uintptr_t)p - (uintptr_t)m.BaseAddress;
  return offset <= m.RegionSize && length <= m.RegionSize - offset;
}
bool request_body(uintptr_t task, std::string &body) {
  uintptr_t input = 0, manager = 0, filters = 0;
  uint32_t count = 0;
  int32_t mode = 0, fps = 0;
  if (!get(task + 0x38, input) || !input || !get(task + 0x30, manager) ||
      !manager || !get(input + 0x64, count) || count > 28 ||
      !get(input + 0x68, filters) || (count && !filters) ||
      !get(input + 0x88, mode) || !get(manager + 0x6094, fps) || fps < 0 ||
      fps > 1000)
    return false;
  body = "{\"result_count\":10,\"filters\":[";
  auto add = [&](const std::string &key, const std::string &value,
                 int comparison, bool numeric) {
    if (body.back() != '[')
      body += ',';
    body += "{\"key\":" + quote(key) + ",\"type\":\"" +
            (numeric ? "numeric" : "string") +
            "\",\"value\":" + (numeric ? value : quote(value)) +
            ",\"comparison\":" + std::to_string(comparison) + "}";
  };
  for (uint32_t i = 0; i < count; ++i) {
    uint32_t key = 0, type = 0, comparison = 0;
    const auto item = filters + (uintptr_t)i * 0x18;
    if (!get(item + 8, key) || !get(item + 12, type) ||
        !get(item + 16, comparison) || comparison > 5)
      return false;
    auto value = filter_value((void *)(input + 8), key, type);
    uint32_t kind = 0;
    int32_t number = 0;
    if (!read(value, kind) || (kind == 1 && !get((uintptr_t)value + 8, number)))
      return false;
    constexpr int compare[] = {1, 2, -1, -2, 0, 3};
    // The game's native search uses STRING comparison for these integer keys.
    add(std::to_string((int32_t)key), std::to_string(number),
        compare[comparison], false);
  }
  add("spec_dev", "dev", 3, false);
  if (mode >= 1 && mode <= 3) {
    const int tolerance = mode == 3 ? 15 : 10;
    add("spec_fps", std::to_string(fps - tolerance), 1, true);
    add("spec_fps", std::to_string(fps + tolerance), -1, true);
  }
  body += "]}";
  return true;
}
bool valid_lobby(uint64_t id) {
  auto instance = (id >> 32) & 0xfffff;
  return (id & 0xffffffff) != 0 && (id >> 56) >= 1 && (id >> 56) <= 4 &&
         ((id >> 52) & 15) == 8 && (instance == 0x40000 || instance == 0x60000);
}
bool fetch(const std::string &body, std::vector<uint64_t> &ids) {
  const auto identity = publication_session();
  if (!identity)
    return false;
  InternetHandle session(WinHttpOpen(L"WWE2K22-native-discovery",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr,
                                     nullptr, 0));
  if (!session || !WinHttpSetTimeouts(session.get(), 1500, 1500, 1500, 2500))
    return false;
  InternetHandle connection(
      WinHttpConnect(session.get(), config.host.c_str(), config.port, 0));
  if (!connection)
    return false;
  InternetHandle request(WinHttpOpenRequest(
      connection.get(), L"POST", L"/lab/lobbies/list", nullptr,
      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
      config.https ? WINHTTP_FLAG_SECURE : 0));
  DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if (!request ||
      !WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &policy,
                        sizeof(policy)))
    return false;
  if (!config.key_header.empty() &&
      !WinHttpAddRequestHeaders(
          request.get(), config.key_header.c_str(), (DWORD)-1,
          WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
    return false;
  std::wstring headers = L"Content-Type: application/json\r\nAccept: "
                         L"application/vnd.wwe2k22.lobby-ids\r\nS: " +
                         std::to_wstring(identity) + L"\r\n";
  if (!WinHttpSendRequest(request.get(), headers.c_str(), (DWORD)-1,
                          (void *)body.data(), (DWORD)body.size(),
                          (DWORD)body.size(), 0) ||
      !WinHttpReceiveResponse(request.get(), nullptr))
    return false;
  DWORD status = 0, size = sizeof(status);
  if (!WinHttpQueryHeaders(
          request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
          nullptr, &status, &size, nullptr) ||
      status != 200) {
    note("lobby-search-http", (int)status);
    return false;
  }
  wchar_t content[80]{};
  size = sizeof(content);
  if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_CONTENT_TYPE, nullptr,
                           content, &size, nullptr) ||
      wcscmp(content, L"application/vnd.wwe2k22.lobby-ids"))
    return false;
  DWORD expected_length = 0;
  size = sizeof(expected_length);
  if (!WinHttpQueryHeaders(request.get(),
                           WINHTTP_QUERY_CONTENT_LENGTH |
                               WINHTTP_QUERY_FLAG_NUMBER,
                           nullptr, &expected_length, &size, nullptr) ||
      expected_length < 8 || expected_length > 88)
    return false;
  const auto deadline = GetTickCount64() + 5000;
  std::array<unsigned char, 89> data{};
  size_t total = 0;
  while (total < data.size()) {
    if (GetTickCount64() > deadline)
      return false;
    DWORD received = 0;
    if (!WinHttpReadData(request.get(), data.data() + total,
                         (DWORD)(data.size() - total), &received))
      return false;
    if (!received)
      break;
    total += received;
  }
  if (total < 8 || total != expected_length || memcmp(data.data(), "W2L1", 4) ||
      identity != publication_session())
    return false;
  uint32_t count = 0;
  memcpy(&count, data.data() + 4, 4);
  if (count > 10 || total != 8 + (size_t)count * 8)
    return false;
  std::vector<uint64_t> result;
  for (uint32_t i = 0; i < count; ++i) {
    uint64_t id = 0;
    memcpy(&id, data.data() + 8 + (size_t)i * 8, 8);
    if (!valid_lobby(id))
      return false;
    for (auto previous : result)
      if (previous == id)
        return false;
    result.push_back(id);
  }
  ids = std::move(result);
  return true;
}
uint64_t search_start(void *object) {
  if (!hooks_ready() || !config.lobbies)
    return original_start(object);
  uint32_t kind = 0;
  if (!read((char *)object + 8, kind) || kind != 4)
    return original_start(object);
  PreserveLastError saved;
  auto task = (uintptr_t)object;
  try {
    if (!writable(object, 0xf8))
      throw 1;
    std::string body;
    std::vector<uint64_t> ids;
    if (!request_body(task, body) || !fetch(body, ids))
      throw 1;
    // Both vectors retain native ownership. Reuse candidate capacity rather
    // than hand-freeing the game's allocator or replacing its callback object.
    reset_results((void *)(task + 0x60));
    *(uint32_t *)(task + 0xac) = 0;
    for (auto id : ids) {
      alignas(8) std::array<unsigned char, 0x44> candidate{};
      memcpy(candidate.data(), &id, 8);
      memset(candidate.data() + 0x14, 0xff, 10 * 4);
      if (append_candidate((void *)(task + 0xa0), candidate.data(), 0, 0) != 1)
        throw 1;
    }
    *(uint32_t *)(task + 0x90) = 2;
    note("lobby-search-candidates", (int)ids.size());
    return 1;
  } catch (...) {
    uintptr_t manager = 0;
    uint32_t operation = 0;
    if (get(task + 0x30, manager) && manager && get(task + 0xc, operation))
      report_error((void *)manager, operation, 0x10000010, 0);
    note("lobby-search-failed");
    return 0;
  }
}
} // namespace
bool install_lobby_search(uintptr_t base) {
  reset_results = (Reset)(base + profile::query_results_reset);
  append_candidate = (Append)(base + profile::query_candidate_append);
  filter_value = (FieldValue)(base + profile::query_filter_value);
  report_error = (Error)(base + profile::platform_error);
  return stage_hook((void *)(base + profile::query_start),
                    (void *)&search_start, (void **)&original_start);
}
#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport)
uint64_t WINAPI WweNativeTestSearch(void *object, void *reset, void *append,
                                    void *field, void *error, void *fallback) {
  original_start = (Start)fallback;
  reset_results = (Reset)reset;
  append_candidate = (Append)append;
  filter_value = (FieldValue)field;
  report_error = (Error)error;
  return search_start(object);
}
#endif
} // namespace wwe
