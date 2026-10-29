// Owned-process fixture: no game or Steam module, loopback service only.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <winhttp.h>
#include <dinput.h>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>
using Capture = int(WINAPI *)(void *, const void *);
using Headers = void(WINAPI *)(const wchar_t *, DWORD);
using VoidTest = int(WINAPI *)();
using ByteTest = size_t(WINAPI *)();
static std::array<unsigned char, 0x58> record{};
static unsigned reader_calls = 0;
static HANDLE pause_entered = nullptr, pause_release = nullptr;
static HANDLE second_entered = nullptr, second_release = nullptr;
static void pause_capture(void *) {
  SetEvent(pause_entered);
  WaitForSingleObject(pause_release, 10000);
}
static void second_pause(void *) {
  SetEvent(second_entered);
  WaitForSingleObject(second_release, 10000);
}
__declspec(noinline) void *image_reader(void *storage, const void *descriptor,
                                         int32_t fallback) {
  ++reader_calls;
  if (storage != (void *)uintptr_t(0x12345678) || !descriptor || fallback != 7)
    return nullptr;
  SetLastError(12345);
  return record.data();
}
static void change_pointer(void *p) { ((unsigned char *)p)[0x40] ^= 8; }
static void change_size(void *p) { ((unsigned char *)p)[0x54] ^= 1; }
static void change_descriptor(void *p) { ((unsigned char *)p)[16] ^= 1; }
static std::vector<unsigned char> dds(size_t size = 132) {
  std::vector<unsigned char> bytes(size);
  uint32_t magic = 0x20534444, header = 124, format = 32;
  memcpy(bytes.data(), &magic, 4);
  memcpy(bytes.data() + 4, &header, 4);
  memcpy(bytes.data() + 76, &format, 4);
  uint32_t flags = 0x100f, one = 1, pitch = 4, rgb = 0x41, bits = 32,
           red = 0x00ff0000, green = 0x0000ff00, blue = 0x000000ff,
           alpha = 0xff000000, texture = 0x1000;
  memcpy(bytes.data() + 8, &flags, 4);
  memcpy(bytes.data() + 12, &one, 4);
  memcpy(bytes.data() + 16, &one, 4);
  memcpy(bytes.data() + 20, &pitch, 4);
  memcpy(bytes.data() + 80, &rgb, 4);
  memcpy(bytes.data() + 88, &bits, 4);
  memcpy(bytes.data() + 92, &red, 4);
  memcpy(bytes.data() + 96, &green, 4);
  memcpy(bytes.data() + 100, &blue, 4);
  memcpy(bytes.data() + 104, &alpha, 4);
  memcpy(bytes.data() + 108, &texture, 4);
  bytes[128] = 0x51;
  return bytes;
}
static void setup(std::vector<unsigned char> &bytes, unsigned id = 1,
                  uint16_t kind = 0) {
  record.fill(0);
  record[0] = 4;
  record[16] = (unsigned char)id;
  memcpy(record.data() + 4, &kind, 2);
  auto p = bytes.data();
  auto size = (uint32_t)bytes.size();
  memcpy(record.data() + 0x40, &p, sizeof(p));
  memcpy(record.data() + 0x54, &size, sizeof(size));
}
static bool barrier(HINTERNET session, INTERNET_PORT port,
                    const wchar_t *path = L"/image-barrier",
                    const wchar_t *verb = L"GET") {
  auto connection = WinHttpConnect(session, L"127.0.0.1", port, 0);
  auto request = WinHttpOpenRequest(connection, verb, path,
                                    nullptr, nullptr,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  bool result = request && WinHttpSendRequest(request, nullptr, 0, nullptr, 0,
                                             0, 0) &&
                WinHttpReceiveResponse(request, nullptr);
  WinHttpCloseHandle(request);
  WinHttpCloseHandle(connection);
  return result;
}
int main(int argc, char **argv) {
  if (argc < 3)
    return 10;
#ifdef WWE_OWNED_ASAN
  // ASan initializes in the EXE CRT before the instrumented proxy is loaded.
  auto asan_proxy = LoadLibraryW(L".\\dinput8.dll");
  if (!asan_proxy)
    return 71;
  auto DirectInput8Create = (decltype(&::DirectInput8Create))
      GetProcAddress(asan_proxy, "DirectInput8Create");
  if (!DirectInput8Create)
    return 72;
#endif
  void *input = nullptr;
  auto hr = DirectInput8Create(GetModuleHandleW(nullptr), 0x800,
                               IID_IDirectInput8W, &input, nullptr);
  if (input)
    ((IUnknown *)input)->Release();
  if (hr != S_OK)
    return 11;
  auto session = WinHttpOpen(L"owned-image-fixture", WINHTTP_ACCESS_TYPE_NO_PROXY,
                              nullptr, nullptr, 0);
  if (!session)
    return 12;
  auto module = GetModuleHandleW(L"dinput8.dll");
  auto capture = (Capture)GetProcAddress(module, "WweNativeTestImageCapture");
  auto headers = (Headers)GetProcAddress(module, "WweNativeTestHeaders");
  auto drain = (VoidTest)GetProcAddress(module, "WweNativeTestImageDrain");
  auto stop = (VoidTest)GetProcAddress(module, "WweNativeTestImageStop");
  auto stopping = (VoidTest)GetProcAddress(module, "WweNativeTestImageStopping");
  auto bytes_used = (ByteTest)GetProcAddress(module, "WweNativeTestImageBytes");
  auto mutate = (void(WINAPI *)(void (*)(void *)))GetProcAddress(
      module, "WweNativeTestImageMutate");
  if (!capture || !headers || !drain || !stop || !stopping || !bytes_used || !mutate)
    return 13;
  auto token = [&](wchar_t ch) {
    auto text = L"X-Sessionid: " + std::wstring(48, ch) + L"\r\n";
    headers(text.c_str(), (DWORD)-1);
  };
  std::string mode = argv[1];
  auto bytes = dds();
  setup(bytes);
  if (mode == "file" || mode == "file-index") {
    if (argc < 5)
      return 14;
    std::wstring session_token;
    for (const char *ch = argv[3]; *ch; ++ch)
      session_token += (wchar_t)(unsigned char)*ch;
    auto header = L"X-Sessionid: " + session_token + L"\r\n";
    headers(header.c_str(), (DWORD)-1);
    if (mode == "file-index") {
      auto install = (int(WINAPI *)(void *))GetProcAddress(
          module, "WweNativeTestImageHook");
      if (!install || !install((void *)&image_reader))
        return 85;
    }
    for (int i = 4; i < argc; ++i) {
      std::ifstream input_file(argv[i], std::ios::binary);
      std::vector<unsigned char> frame(
          (std::istreambuf_iterator<char>(input_file)),
          std::istreambuf_iterator<char>());
      uint32_t size = 0;
      if (frame.size() < 44)
        return 15;
      memcpy(&size, frame.data() + 40, 4);
      if (memcmp(frame.data(), "W2IMG001", 8) || size > 16 * 1024 * 1024 ||
          frame.size() != size + 44)
        return 16;
      bytes.assign(frame.begin() + 44, frame.end());
      setup(bytes);
      memcpy(record.data(), frame.data() + 8, 32);
      if (mode == "file-index") {
        record[0] &= ~4;
        uint32_t index = (uint32_t)(i - 4);
        memcpy(record.data() + 12, &index, 4);
        std::array<unsigned char, 32> requested{};
        memcpy(requested.data(), record.data(), 32);
        memset(requested.data() + 16, 0, 16);
        volatile auto fn = &image_reader;
        if (fn((void *)uintptr_t(0x12345678), requested.data(), 7) !=
                record.data() ||
            !drain())
          return 86;
      } else if (!capture(record.data(), record.data()) || !drain())
        return 17;
    }
  } else if (mode == "hook-index") {
    auto install =
        (int(WINAPI *)(void *))GetProcAddress(module, "WweNativeTestImageHook");
    if (!install || !install((void *)&image_reader))
      return 80;
    token(L'a');
    volatile auto fn = &image_reader;
    for (unsigned i = 0; i < 3; ++i) {
      setup(bytes, 10 + i, i == 0 ? 0 : i == 1 ? 31 : 61);
      record[0] =
          0; // Native indexed record, with its canonical publication UUID.
      uint16_t variant = 2;
      uint32_t index = 101 + i;
      memcpy(record.data() + 10, &variant, 2);
      memcpy(record.data() + 12, &index, 4);
      std::array<unsigned char, 32> requested{};
      memcpy(requested.data(), record.data(), 32);
      memset(requested.data() + 16, 0,
             16); // An index lookup carries no requested UUID.
      auto result = fn((void *)uintptr_t(0x12345678), requested.data(), 7);
      if (result != record.data() || reader_calls != i + 1 ||
          GetLastError() != 12345 || !drain())
        return 81;
    }
    std::array<unsigned char, 32> requested{};
    memcpy(requested.data(), record.data(), 32);
    memset(requested.data() + 16, 0, 16);
    for (auto offset : {4, 10, 12}) {
      auto wrong = requested;
      wrong[offset] ^= 1;
      if (fn((void *)uintptr_t(0x12345678), wrong.data(), 7) != record.data() ||
          !drain())
        return 82;
    }
    // A UUID lookup must still reject a fallback with another image identity.
    record[0] = 4;
    auto wrong = requested;
    wrong[0] = 4;
    wrong[16] = 88;
    if (fn((void *)uintptr_t(0x12345678), wrong.data(), 7) != record.data() ||
        !drain())
      return 83;
    record[0] = 0;
    memset(record.data() + 16, 0, 16);
    if (fn((void *)uintptr_t(0x12345678), requested.data(), 7) !=
            record.data() ||
        !drain())
      return 84;
  } else if (mode == "hook") {
    auto install = (int(WINAPI *)(void *))GetProcAddress(
        module, "WweNativeTestImageHook");
    if (!install || !install((void *)&image_reader))
      return 18;
    token(L'a');
    volatile auto fn = &image_reader;
    auto result = fn((void *)uintptr_t(0x12345678), record.data(), 7);
    if (result != record.data() || reader_calls != 1 || GetLastError() != 12345 ||
        !drain())
      return 19;
    std::array<unsigned char, 32> wrong{};
    memcpy(wrong.data(), record.data(), 32);
    wrong[16] = 99;
    if (fn((void *)uintptr_t(0x12345678), wrong.data(), 7) != record.data() ||
        reader_calls != 2 || !drain())
      return 48;
  } else if (mode == "marker") {
    auto port = (INTERNET_PORT)atoi(argv[2]);
    if (!barrier(session, port, L"/api/ContentMetaGet", L"POST") ||
        !barrier(session, port, L"/api/ContentMetaGet", L"GET") ||
        !barrier(session, port, L"/other", L"POST"))
      return 49;
  } else if (mode == "malformed") {
    std::array<unsigned char, 32> expected{};
    memcpy(expected.data(), record.data(), 32);
    if (capture(nullptr, expected.data()) || capture((void *)-0x30, expected.data()) ||
        capture(record.data(), (void *)1))
      return 20;
    for (auto callback : {change_pointer, change_size, change_descriptor}) {
      setup(bytes);
      memcpy(expected.data(), record.data(), 32);
      mutate(callback);
      if (capture(record.data(), expected.data()))
        return 21;
    }
    setup(bytes);
    expected[16] = 2;
    if (capture(record.data(), expected.data()))
      return 22;
    setup(bytes, 1, 99);
    if (capture(record.data(), record.data()))
      return 23;
    setup(bytes, 0);
    if (capture(record.data(), record.data()))
      return 24;
    setup(bytes);
    uint32_t too_big = 16 * 1024 * 1024 + 1;
    memcpy(record.data() + 0x54, &too_big, 4);
    if (capture(record.data(), record.data()))
      return 25;
    setup(bytes);
    bytes[0] = 0;
    if (capture(record.data(), record.data()))
      return 26;
    bytes[0] = 'D';
    uint32_t width = 0;
    memcpy(bytes.data() + 16, &width, 4);
    if (capture(record.data(), record.data()))
      return 51;
    width = 16385;
    memcpy(bytes.data() + 16, &width, 4);
    if (capture(record.data(), record.data()))
      return 52;
    width = 1;
    memcpy(bytes.data() + 16, &width, 4);
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    auto guard = VirtualAlloc(nullptr, info.dwPageSize, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    memcpy(guard, record.data(), record.size());
    DWORD old = 0;
    VirtualProtect(guard, info.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &old);
    if (capture(guard, record.data()))
      return 27;
    MEMORY_BASIC_INFORMATION region{};
    VirtualQuery(guard, &region, sizeof(region));
    if (!(region.Protect & PAGE_GUARD))
      return 28;
    auto pointer = guard;
    memcpy(record.data() + 0x40, &pointer, sizeof(pointer));
    if (capture(record.data(), record.data()))
      return 29;
    VirtualQuery(guard, &region, sizeof(region));
    if (!(region.Protect & PAGE_GUARD))
      return 30;
    VirtualFree(guard, 0, MEM_RELEASE);
    if (bytes_used())
      return 31;
  } else if (mode == "capture-fuzz") {
    // Every borrowed range belongs to this fixture. The last three pages of
    // each region cover guard, inaccessible and decommitted memory states.
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const size_t page = info.dwPageSize;
    auto data_region = (unsigned char *)VirtualAlloc(
        nullptr, page * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    auto record_region = (unsigned char *)VirtualAlloc(
        nullptr, page * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data_region || !record_region)
      return 73;
    memcpy(data_region + 64, bytes.data(), bytes.size());
    memcpy(data_region + page - bytes.size(), bytes.data(), bytes.size());
    DWORD old = 0;
    bool protected_pages =
        VirtualProtect(data_region + page, page, PAGE_READWRITE | PAGE_GUARD, &old) &&
        VirtualProtect(record_region + page, page, PAGE_READWRITE | PAGE_GUARD, &old) &&
        VirtualProtect(data_region + page * 2, page, PAGE_NOACCESS, &old) &&
        VirtualProtect(record_region + page * 2, page, PAGE_NOACCESS, &old) &&
        VirtualFree(data_region + page * 3, page, MEM_DECOMMIT) &&
        VirtualFree(record_region + page * 3, page, MEM_DECOMMIT);
    if (!protected_pages)
      return 74;
    uint32_t random_state = 0x5eed2c22;
    auto next = [&] {
      random_state ^= random_state << 13;
      random_state ^= random_state >> 17;
      random_state ^= random_state << 5;
      return random_state;
    };
    std::array<std::array<unsigned char, 16>, 8> identities{};
    for (unsigned id = 1; id < identities.size(); ++id) {
      for (auto &value : identities[id])
        value = (unsigned char)next();
      identities[id][0] = (unsigned char)id;
    }
    const uint32_t sizes[] = {0, 127, 128, 129, 132, 256, 4096,
                              16 * 1024 * 1024, UINT32_MAX};
    unsigned controls = 0, accepted = 0;
    size_t peak = 0;
    bool controls_ok = true, budget_ok = true;
    for (unsigned iteration = 0; iteration < 20000; ++iteration) {
      for (unsigned i = 0; i < 16; ++i)
        record[i] = (unsigned char)next();
      uint16_t kinds[] = {0, 31, 61, 9, UINT16_MAX, (uint16_t)next()};
      uint16_t kind = kinds[next() % 6];
      unsigned id = next() % identities.size();
      memcpy(record.data() + 4, &kind, sizeof(kind));
      memcpy(record.data() + 16, identities[id].data(), 16);
      uintptr_t data_options[] = {
          0, (uintptr_t)(data_region + 64), (uintptr_t)(data_region + 65),
          (uintptr_t)(data_region + page - bytes.size()),
          (uintptr_t)(data_region + page + 8),
          (uintptr_t)(data_region + page * 2 + 8),
          (uintptr_t)(data_region + page * 3 + 8), 1, UINTPTR_MAX - 63};
      uintptr_t pointer = data_options[next() % 9];
      uint32_t length = sizes[next() % 9];
      // Huge copies are normally rejected by pointer/header validation. Four
      // deliberate valid-header probes exercise allocation then guard failure.
      if (length == 16 * 1024 * 1024)
        pointer = data_options[4 + next() % 5];
      bool large_probe = iteration % 5000 == 4999;
      if (large_probe) {
        kind = 0;
        memcpy(record.data() + 4, &kind, sizeof(kind));
        memcpy(record.data() + 16, identities[1].data(), 16);
        pointer = (uintptr_t)(data_region + page - bytes.size());
        length = 16 * 1024 * 1024;
      }
      bool control = iteration % 97 == 0;
      if (control) {
        kind = 0;
        memcpy(record.data() + 4, &kind, sizeof(kind));
        memcpy(record.data() + 16, identities[1].data(), 16);
        pointer = (uintptr_t)(data_region + 64);
        length = (uint32_t)bytes.size();
      }
      memcpy(record.data() + 0x40, &pointer, sizeof(pointer));
      memcpy(record.data() + 0x54, &length, sizeof(length));
      auto valid_record = record_region + 64;
      auto edge_record = record_region + page - record.size();
      auto expected = record_region + 256;
      auto mismatch = record_region + 512;
      memcpy(valid_record, record.data(), record.size());
      memcpy(edge_record, record.data(), record.size());
      memcpy(expected, record.data(), 32);
      memcpy(mismatch, record.data(), 32);
      mismatch[16] ^= 0x80;
      void *record_options[] = {
          valid_record, edge_record, nullptr, record_region + page - 16,
          record_region + page + 8, record_region + page * 2 + 8,
          record_region + page * 3 + 8, (void *)1, (void *)(UINTPTR_MAX - 15)};
      const void *expected_options[] = {
          expected, valid_record, mismatch, nullptr, record_region + page - 16,
          record_region + page + 8, record_region + page * 2 + 8,
          record_region + page * 3 + 8, (void *)(UINTPTR_MAX - 15)};
      void *borrowed_record = control || large_probe ? valid_record : record_options[next() % 9];
      const void *borrowed_expected = control || large_probe ? expected : expected_options[next() % 9];
      int result = capture(borrowed_record, borrowed_expected);
      accepted += result != 0;
      if (control) {
        ++controls;
        controls_ok &= result != 0;
      }
      auto sample = bytes_used();
      if (sample > peak)
        peak = sample;
      budget_ok &= sample <= 64 * 1024 * 1024;
    }
    MEMORY_BASIC_INFORMATION data_guard{}, record_guard{};
    bool guards_ok =
        VirtualQuery(data_region + page, &data_guard, sizeof(data_guard)) &&
        VirtualQuery(record_region + page, &record_guard, sizeof(record_guard)) &&
        (data_guard.Protect & PAGE_GUARD) && (record_guard.Protect & PAGE_GUARD);
    bool stopped = stop() != 0;
    bool empty = bytes_used() == 0;
    VirtualFree(data_region, 0, MEM_RELEASE);
    VirtualFree(record_region, 0, MEM_RELEASE);
    printf("{\"fuzz_seed\":%u,\"fuzz_cases\":20000,\"valid_controls\":%u,\"accepted\":%u,\"peak_owned_bytes\":%zu}\n",
           0x5eed2c22u, controls, accepted, peak);
    if (!controls_ok || !budget_ok || !guards_ok || !stopped || !empty)
      return 75;
  } else if (mode == "parallel" || mode == "parallel-budget") {
    bytes = dds(mode == "parallel" ? 4 * 1024 * 1024 + 128 : 16 * 1024 * 1024);
    std::array<std::array<unsigned char, 0x58>, 8> records{};
    for (unsigned i = 0; i < records.size(); ++i) {
      setup(bytes, i + 1);
      records[i] = record;
    }
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<unsigned> ready{0}, finished{0}, accepted{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < records.size(); ++i)
      threads.emplace_back([&, i] {
        ++ready;
        WaitForSingleObject(start, 10000);
        accepted += capture(records[i].data(), records[i].data()) != 0;
        ++finished;
      });
    while (ready != records.size())
      Sleep(1);
    size_t peak = 0;
    SetEvent(start);
    while (finished != records.size()) {
      auto sample = bytes_used();
      if (sample > peak)
        peak = sample;
      SwitchToThread();
    }
    for (auto &thread : threads)
      thread.join();
    CloseHandle(start);
    printf("{\"parallel_captures\":%u,\"peak_owned_bytes\":%zu}\n", accepted.load(), peak);
    if (accepted != (mode == "parallel" ? 8u : 3u) ||
        peak > 64 * 1024 * 1024 || bytes_used() > 64 * 1024 * 1024 ||
        !stop() || bytes_used())
      return 63;
  } else if (mode == "burst") {
    bytes = dds(256 * 1024);
    for (unsigned id = 1; id <= 40; ++id) {
      setup(bytes, id);
      if (!capture(record.data(), record.data()))
        return 64;
    }
    if (!stop() || bytes_used())
      return 65;
  } else if (mode == "stop-race") {
    bytes = dds(4 * 1024 * 1024 + 128);
    setup(bytes);
    pause_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    pause_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    mutate(pause_capture);
    int captured = -1, stopped = -1;
    std::atomic<bool> stop_done{false};
    std::thread producer([&] { captured = capture(record.data(), record.data()); });
    bool paused = WaitForSingleObject(pause_entered, 5000) == WAIT_OBJECT_0;
    std::thread stopper([&] { stopped = stop(); stop_done = true; });
    auto began = GetTickCount64();
    while (!stopping() && GetTickCount64() - began < 1000)
      Sleep(1);
    Sleep(25);
    bool held = !stop_done && bytes_used() == bytes.size() + 44;
    SetEvent(pause_release);
    producer.join();
    stopper.join();
    CloseHandle(pause_entered);
    CloseHandle(pause_release);
    if (!paused || !held || captured || !stopped || bytes_used() ||
        capture(record.data(), record.data()))
      return 66;
  } else if (mode.rfind("coalesce-", 0) == 0 && mode.find("race") != mode.npos) {
    bytes = dds(4 * 1024 * 1024 + 128);
    setup(bytes, 1);
    if (!capture(record.data(), record.data()))
      return 67;
    Sleep(50);
    setup(bytes, 2);
    if (!capture(record.data(), record.data()))
      return 68;
    auto before = bytes_used();
    auto older_bytes = bytes, newer_bytes = bytes;
    if (mode != "coalesce-read-race")
      older_bytes[128] = 0x52;
    newer_bytes[128] = 0x53;
    setup(older_bytes, 2);
    auto older_record = record;
    setup(newer_bytes, 2);
    auto newer_record = record;
    pause_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    pause_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    mutate(pause_capture);
    int older_result = -1;
    std::thread older([&] { older_result = capture(older_record.data(), older_record.data()); });
    bool paused = WaitForSingleObject(pause_entered, 5000) == WAIT_OBJECT_0;
    bool newer_ok = false;
    if (mode == "coalesce-restore-race") {
      setup(bytes, 2);
      auto unchanged_record = record;
      second_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      second_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      mutate(second_pause);
      int unchanged_result = -1;
      std::thread unchanged([&] { unchanged_result = capture(unchanged_record.data(), unchanged_record.data()); });
      bool second_paused = WaitForSingleObject(second_entered, 5000) == WAIT_OBJECT_0;
      SetEvent(pause_release);
      older.join();
      SetEvent(second_release);
      unchanged.join();
      newer_ok = second_paused && unchanged_result;
      CloseHandle(second_entered);
      CloseHandle(second_release);
    } else {
      if (mode == "coalesce-failed-race")
        newer_bytes[0] = 0;
      int result = capture(newer_record.data(), newer_record.data());
      newer_ok = mode == "coalesce-failed-race" ? !result : result != 0;
      SetEvent(pause_release);
      older.join();
    }
    CloseHandle(pause_entered);
    CloseHandle(pause_release);
    if (!paused || !older_result || !newer_ok || bytes_used() != before)
      return 69;
    token(L'a');
    if (!drain())
      return 70;
  } else if (mode == "bounds" || mode == "queue") {
    if (mode == "bounds") {
      bytes = dds(16 * 1024 * 1024);
      setup(bytes);
    }
    unsigned accepted = 0;
    for (unsigned i = 0; i < 100; ++i) {
      record[16] = (unsigned char)(i + 1);
      accepted += capture(record.data(), record.data()) != 0;
    }
    if (!accepted || bytes_used() > 64 * 1024 * 1024 ||
        (mode == "bounds" && accepted > 3) ||
        (mode == "queue" && accepted > 65))
      return 32;
    if (!stop() || bytes_used() || capture(record.data(), record.data()))
      return 33;
  } else if (mode == "coalesce" || mode == "coalesce-budget" ||
             mode == "coalesce-typical") {
    if (mode != "coalesce") {
      bytes = dds(mode == "coalesce-budget" ? 16 * 1024 * 1024 :
                                             4 * 1024 * 1024 + 128);
      setup(bytes);
    }
    if (!capture(record.data(), record.data()))
      return 53;
    Sleep(50); // Keep one owned item staged while the REST session is absent.
    unsigned last = mode == "coalesce" ? 65 : 3;
    for (unsigned id = 2; id <= last; ++id) {
      setup(bytes, id);
      if (!capture(record.data(), record.data()))
        return 54;
    }
    auto before = bytes_used();
    setup(bytes, 2);
    record[1] ^= 0x80;
    LARGE_INTEGER frequency{}, beginning{}, ending{};
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&beginning);
    for (unsigned i = 0; i < 20; ++i)
      if (!capture(record.data(), record.data()))
        return 55;
    QueryPerformanceCounter(&ending);
    printf("{\"duplicate_samples\":20,\"dds_bytes\":%zu,\"average_us\":%.1f}\n",
           bytes.size(), double(ending.QuadPart - beginning.QuadPart) * 1000000 /
                             double(frequency.QuadPart) / 20);
    bytes[128] = 0x52;
    if (!capture(record.data(), record.data()) || bytes_used() != before)
      return 56;
    if (mode == "coalesce") {
      setup(bytes, 66);
      if (capture(record.data(), record.data()))
        return 57;
      token(L'a');
      if (!drain())
        return 58;
    } else if (!stop() || bytes_used()) {
      return 59;
    }
  } else if (mode == "disabled") {
    if (capture(record.data(), record.data()) || bytes_used())
      return 34;
  } else {
    if (mode != "stage")
      token(L'a');
    if (!capture(record.data(), record.data()))
      return 35;
    if (mode == "stage") {
      // Payload is owned before REST login, not borrowed by the worker.
      bytes[128] = 0xff;
      token(L'a');
      if (!drain())
        return 36;
    } else if (mode == "auth" || mode == "rotation" || mode == "inflight") {
      if (mode == "auth" || mode == "inflight") {
        if (!barrier(session, (INTERNET_PORT)atoi(argv[2])))
          return 37;
        token(L'b');
        if (mode == "inflight" &&
            !barrier(session, (INTERNET_PORT)atoi(argv[2]), L"/image-release"))
          return 50;
        if (!drain())
          return 38;
      } else {
        if (!drain())
          return 39;
        token(L'b');
        if (!capture(record.data(), record.data()) || !drain())
          return 40;
      }
    } else if (mode == "permanent" || mode == "retry-cap") {
      if (!drain() || !capture(record.data(), record.data()) || !drain())
        return 60;
      bytes[128] = 0x52;
      if (!capture(record.data(), record.data()) || !drain())
        return 61;
      if (mode == "permanent") {
        token(L'b');
        if (!capture(record.data(), record.data()) || !drain())
          return 62;
      }
    } else if (mode == "basic") {
      if (!drain())
        return 41;
      // Same identity+SHA acknowledged once despite descriptor flag variation.
      record[1] ^= 0x80;
      std::array<unsigned char, 32> requested{};
      memcpy(requested.data(), record.data(), 32);
      requested[1] ^= 0x40;
      if (!capture(record.data(), requested.data()) || !drain())
        return 42;
      for (uint16_t kind : {uint16_t(31), uint16_t(61)}) {
        setup(bytes, kind + 2, kind);
        if (!capture(record.data(), record.data()) || !drain())
          return 43;
      }
      setup(bytes, 1);
      bytes[128] = 0x52;
      if (!capture(record.data(), record.data()) || !drain())
        return 44;
      bytes[128] = 0x51;
      if (!capture(record.data(), record.data()) || !drain())
        return 45;
    } else if (!drain()) {
      return 46;
    }
  }
  if (!stop())
    return 47;
  WinHttpCloseHandle(session);
  puts("{\"owned_images\":true,\"game_started\":false}");
  return 0;
}
