#include "resources.hpp"
#include "profile.hpp"
#include "MinHook.h"
#include <array>
#include <atomic>
#include <bcrypt.h>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace wwe {
namespace {
constexpr size_t image_limit = 16 * 1024 * 1024;
constexpr size_t memory_limit = 64 * 1024 * 1024;
constexpr size_t queue_limit = 64, capture_limit = 16, cache_limit = 256;
constexpr ULONGLONG lifetime = 5 * 60 * 1000;
using Descriptor = std::array<unsigned char, 32>;
using Identity = std::array<unsigned char, 18>;
using Digest = std::array<unsigned char, 32>;
std::atomic<size_t> owned_bytes{0};
struct Work {
  std::vector<unsigned char> frame;
  ULONGLONG created = 0;
  uint64_t sequence = 0;
  size_t charged = 0;
  ~Work() {
    std::vector<unsigned char>().swap(frame);
    if (charged)
      owned_bytes.fetch_sub(charged);
  }
};
std::mutex queue_lock;
std::deque<std::shared_ptr<Work>> queue;
struct Generation { uint64_t latest = 0; unsigned readers = 0; };
std::map<Identity, Generation> generations;
unsigned capture_count = 0;
uint64_t sequence_counter = 0;
[[maybe_unused]] bool active = false;
KernelHandle work_event, stop_event, captures_idle, worker;
volatile LONG stopping = 0;
using ImageReader = void *(*)(void *, const void *, int32_t);
ImageReader original_reader = nullptr;
thread_local bool native_transport = false;
#ifdef WWE_OWNED_TEST
std::atomic<void (*)(void *)> mutate_once{nullptr};
#endif

struct CaptureGuard {
  Identity identity{};
  bool entered = false;
  ~CaptureGuard() {
    if (!entered)
      return;
    std::lock_guard<std::mutex> lock(queue_lock);
    auto it = generations.find(identity);
    if (it != generations.end() && !--it->second.readers)
      generations.erase(it);
    if (!--capture_count)
      SetEvent(captures_idle.get());
  }
};
bool reserve_bytes(size_t count) {
  auto current = owned_bytes.load();
  while (current <= memory_limit - count)
    if (owned_bytes.compare_exchange_weak(current, current + count))
      return true;
  return false;
}

// VirtualQuery rejects guards before ReadProcessMemory, which provides the
// fault boundary if the borrowed allocation changes concurrently.
bool guarded_read(const void *source, void *out, size_t size) noexcept {
  uintptr_t cursor = (uintptr_t)source;
  if (!cursor || !size || size > UINTPTR_MAX - cursor)
    return false;
  const uintptr_t end = cursor + size;
  while (cursor < end) {
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery((void *)cursor, &region, sizeof(region)) ||
        region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(region.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY)))
      return false;
    auto next = (uintptr_t)region.BaseAddress + region.RegionSize;
    if (next <= cursor)
      return false;
    cursor = next < end ? next : end;
  }
  return read_memory(source, out, size);
}
template <class T> bool field(const void *record, size_t offset, T &out) {
  auto address = (uintptr_t)record;
  return address && offset <= UINTPTR_MAX - address &&
         guarded_read((void *)(address + offset), &out, sizeof(out));
}
bool valid_dds(const unsigned char *bytes) {
  uint32_t magic = 0, header = 0, format = 0, height = 0, width = 0;
  memcpy(&magic, bytes, 4);
  memcpy(&header, bytes + 4, 4);
  memcpy(&format, bytes + 76, 4);
  memcpy(&height, bytes + 12, 4);
  memcpy(&width, bytes + 16, 4);
  return magic == 0x20534444 && header == 124 && format == 32 &&
         width && height && width <= 16384 && height <= 16384;
}
bool capture(void *record, const Descriptor &requested) noexcept {
  PreserveLastError error;
  CaptureGuard guard;
  try {
    if (!hooks_ready() || !config.content ||
        InterlockedCompareExchange(&stopping, 0, 0))
      return false;
    memcpy(guard.identity.data(), requested.data() + 4, 2);
    memcpy(guard.identity.data() + 2, requested.data() + 16, 16);
    uint64_t sequence = 0;
    std::shared_ptr<Work> pending;
    auto matches = [&](const std::shared_ptr<Work> &item) {
      return !memcmp(item->frame.data() + 8 + 16, requested.data() + 16, 16) &&
             !memcmp(item->frame.data() + 8 + 4, requested.data() + 4, 2);
    };
    {
      // Only bounded queue/generation metadata is protected here. Native
      // reads, payload comparisons, allocation and network run outside it.
      std::lock_guard<std::mutex> lock(queue_lock);
      if (!worker || capture_count >= capture_limit ||
          InterlockedCompareExchange(&stopping, 0, 0))
        return false;
      for (const auto &item : queue)
        if (matches(item)) {
          pending = item;
          break;
        }
      if (!pending && queue.size() >= queue_limit)
        return false;
      auto &generation = generations[guard.identity];
      sequence = ++sequence_counter;
      ++generation.readers;
      if (!capture_count++)
        ResetEvent(captures_idle.get());
      guard.entered = true;
    }
    Descriptor descriptor{}, after{};
    uintptr_t data = 0, next_data = 0;
    uint32_t size = 0, next_size = 0;
    if (!guarded_read(record, descriptor.data(), descriptor.size()) ||
        memcmp(descriptor.data() + 16, requested.data() + 16, 16) ||
        memcmp(descriptor.data() + 4, requested.data() + 4, 2) ||
        !field(record, 0x40, data) || !field(record, 0x54, size))
      return false;
    uint16_t kind = 0;
    memcpy(&kind, descriptor.data() + 4, sizeof(kind));
    bool nonzero = false;
    for (size_t i = 16; i < 32; ++i)
      nonzero |= descriptor[i] != 0;
    if ((kind != 0 && kind != 31 && kind != 61) || !nonzero || size < 128 ||
        size > image_limit || !data || size > UINTPTR_MAX - data)
      return false;
    std::array<unsigned char, 128> header{};
    if (!guarded_read((void *)data, header.data(), header.size()) ||
        !valid_dds(header.data()))
      return false;
    auto stable = [&] {
#ifdef WWE_OWNED_TEST
      if (auto fn = mutate_once.exchange(nullptr))
        fn(record);
#endif
      return guarded_read(record, after.data(), after.size()) &&
             field(record, 0x40, next_data) && field(record, 0x54, next_size) &&
             descriptor == after && data == next_data && size == next_size &&
             !InterlockedCompareExchange(&stopping, 0, 0);
    };
    if (pending && pending->frame.size() == size + 44) {
      // A shared immutable snapshot remains charged until its last reader
      // releases it, even if the worker pops it or another capture replaces it.
      std::array<unsigned char, 64 * 1024> chunk{};
      bool same = true;
      for (size_t offset = 0; offset < size;) {
        size_t count = size - offset < chunk.size() ? size - offset : chunk.size();
        if (!guarded_read((void *)(data + offset), chunk.data(), count))
          return false;
        if (memcmp(chunk.data(), pending->frame.data() + 44 + offset, count)) {
          same = false;
          break;
        }
        offset += count;
      }
      if (same) {
        if (!stable())
          return false;
        std::shared_ptr<Work> retired;
        {
          std::lock_guard<std::mutex> lock(queue_lock);
          auto generation = generations.find(guard.identity);
          if (InterlockedCompareExchange(&stopping, 0, 0) ||
              generation == generations.end())
            return false;
          if (generation->second.latest > sequence)
            return true;
          auto existing = queue.end();
          for (auto it = queue.begin(); it != queue.end(); ++it)
            if (matches(*it)) {
              existing = it;
              break;
            }
          // The worker may have popped the snapshot, or an older concurrent
          // capture may have replaced it. Preserve this newer stable version.
          if (existing == queue.end()) {
            if (queue.size() >= queue_limit)
              return false;
            queue.push_back(pending);
          } else if (*existing != pending) {
            retired = std::move(*existing);
            *existing = pending;
          }
          generation->second.latest = sequence;
          SetEvent(work_event.get());
        }
        return true;
      }
    }
    const size_t charge = size + 44;
    if (!reserve_bytes(charge)) {
      if (!pending)
        return false;
      std::shared_ptr<Work> retired;
      {
        std::lock_guard<std::mutex> lock(queue_lock);
        auto generation = generations.find(guard.identity);
        if (InterlockedCompareExchange(&stopping, 0, 0) ||
            generation == generations.end() ||
            generation->second.latest > sequence)
          return false;
        for (auto it = queue.begin(); it != queue.end(); ++it)
          if (*it == pending && pending.use_count() == 2) {
            retired = std::move(*it);
            queue.erase(it);
            break;
          }
      }
      retired.reset();
      pending.reset();
      if (!reserve_bytes(charge))
        return false;
    }
    struct Reservation {
      size_t count;
      ~Reservation() { if (count) owned_bytes.fetch_sub(count); }
    } reservation{charge};
    auto item = std::make_shared<Work>();
    item->charged = std::exchange(reservation.count, 0);
    item->frame.resize(charge);
    memcpy(item->frame.data(), "W2IMG001", 8);
    memcpy(item->frame.data() + 8, descriptor.data(), descriptor.size());
    memcpy(item->frame.data() + 40, &size, sizeof(size));
    if (!guarded_read((void *)data, item->frame.data() + 44, size) ||
        !valid_dds(item->frame.data() + 44) || !stable())
      return false;
    item->created = GetTickCount64();
    item->sequence = sequence;
    std::shared_ptr<Work> retired;
    {
      std::lock_guard<std::mutex> lock(queue_lock);
      if (InterlockedCompareExchange(&stopping, 0, 0))
        return false;
      auto generation = generations.find(guard.identity);
      if (generation == generations.end() ||
          generation->second.latest > sequence)
        return true; // A newer observation owns this identity's next version.
      auto existing = queue.end();
      for (auto it = queue.begin(); it != queue.end(); ++it)
        if (matches(*it)) {
          existing = it;
          break;
        }
      if (existing != queue.end()) {
        retired = std::move(*existing);
        *existing = std::move(item);
      } else {
        if (queue.size() >= queue_limit)
          return false;
        queue.push_back(std::move(item));
      }
      generation->second.latest = sequence;
      SetEvent(work_event.get());
    }
    return true;
  } catch (...) {
    return false;
  }
}

void *image_hook(void *storage, const void *descriptor, int32_t fallback) {
  Descriptor requested{};
  DWORD before = GetLastError();
  bool valid = guarded_read(descriptor, requested.data(), requested.size());
  SetLastError(before);
  void *result = original_reader(storage, descriptor, fallback);
  if (valid)
    capture(result, requested);
  return result;
}
bool digest(const Work &work, Digest &result) {
  struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
  } algorithm;
  if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return false;
  DWORD bytes = 0, used = 0;
  if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, (PUCHAR)&bytes,
                        sizeof(bytes), &used, 0) < 0)
    return false;
  std::vector<unsigned char> object(bytes);
  struct Hash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() { if (value) BCryptDestroyHash(value); }
  } hash;
  return BCryptCreateHash(algorithm.value, &hash.value, object.data(), bytes,
                           nullptr, 0, 0) >= 0 &&
         BCryptHashData(hash.value, (PUCHAR)work.frame.data() + 44,
                         (ULONG)work.frame.size() - 44, 0) >= 0 &&
         BCryptFinishHash(hash.value, result.data(), (ULONG)result.size(), 0) >= 0;
}
enum class Result { Success, Retry, Authentication, Permanent };
Result upload(const Work &work, const std::wstring &token) {
  struct TransportScope {
    TransportScope() { native_transport = true; }
    ~TransportScope() { native_transport = false; }
  } scope;
  InternetHandle session(WinHttpOpen(L"WWE2K22-native-images",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr,
                                    nullptr, 0));
  if (!session || !WinHttpSetTimeouts(session.get(), 5000, 10000, 60000, 30000))
    return Result::Retry;
  InternetHandle connection(
      WinHttpConnect(session.get(), config.host.c_str(), config.port, 0));
  if (!connection)
    return Result::Retry;
  InternetHandle request(WinHttpOpenRequest(
      connection.get(), L"POST", L"/lab/images/sync", nullptr,
      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
      config.https ? WINHTTP_FLAG_SECURE : 0));
  if (!request)
    return Result::Retry;
  DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
                        &redirects, sizeof(redirects)))
    return Result::Retry;
  if (config.https) {
    DWORD secure = 0, bytes = sizeof(secure);
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS,
                          &secure, sizeof(secure)) ||
        !WinHttpQueryOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS,
                            &secure, &bytes) || secure)
      return Result::Permanent;
  }
  if (!config.key_header.empty() &&
      !WinHttpAddRequestHeaders(request.get(), config.key_header.c_str(),
                                (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD |
                                               WINHTTP_ADDREQ_FLAG_REPLACE))
    return Result::Retry;
  auto headers = L"Content-Type: application/octet-stream\r\nX-Sessionid: " +
                 token + L"\r\n";
  if (InterlockedCompareExchange(&stopping, 0, 0) ||
      image_rest_session() != token)
    return Result::Retry;
  DWORD bytes = (DWORD)work.frame.size();
  BOOL sent = WinHttpSendRequest(request.get(), headers.c_str(), (DWORD)-1,
                                 (void *)work.frame.data(), bytes, bytes, 0) &&
              WinHttpReceiveResponse(request.get(), nullptr);
  DWORD error = GetLastError();
  DWORD status = 0, length = sizeof(status);
  if (sent)
    WinHttpQueryHeaders(request.get(),
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &status, &length, nullptr);
  note("image-sync-result", (int)status);
  if (status >= 200 && status < 300)
    return Result::Success;
  if (!sent && error == ERROR_WINHTTP_SECURE_FAILURE)
    return Result::Permanent;
  if (status == 401 || status == 403)
    return Result::Authentication;
  return !status || status == 408 ||
                 status == 425 || status == 429 || status >= 500
             ? Result::Retry
             : Result::Permanent;
}
DWORD WINAPI image_worker(void *) {
  struct Acknowledgement { Digest hash; ULONGLONG when; };
  std::map<Identity, Acknowledgement> acknowledged;
  // Rejections are not acknowledgements. Their short cooldown prevents a
  // repeatedly rendered collision from hammering the private endpoint.
  std::map<Identity, Acknowledgement> rejected;
  std::wstring previous_session;
  for (;;) {
    HANDLE events[] = {stop_event.get(), work_event.get()};
    if (WaitForMultipleObjects(2, events, FALSE, INFINITE) != WAIT_OBJECT_0 + 1)
      return 0;
    for (;;) {
      std::shared_ptr<Work> item;
      {
        std::lock_guard<std::mutex> lock(queue_lock);
        if (InterlockedCompareExchange(&stopping, 0, 0)) {
          queue.clear();
          return 0;
        }
        if (queue.empty())
          break;
        item = std::move(queue.front());
        queue.pop_front();
        active = true;
      }
      try {
        Digest hash{};
        Identity identity{};
        memcpy(identity.data(), item->frame.data() + 8 + 4, 2);
        memcpy(identity.data() + 2, item->frame.data() + 8 + 16, 16);
        if (digest(*item, hash)) {
          unsigned failures = 0;
          std::wstring rejected_session;
          while (GetTickCount64() - item->created < lifetime &&
                 !InterlockedCompareExchange(&stopping, 0, 0)) {
            auto token = image_rest_session();
            if (previous_session != token) {
              acknowledged.clear();
              rejected.clear();
              previous_session = token;
            }
            auto known = acknowledged.find(identity);
            if (!token.empty() && known != acknowledged.end() &&
                known->second.hash == hash &&
                GetTickCount64() - known->second.when < 30000)
              break;
            auto blocked = rejected.find(identity);
            if (!token.empty() && blocked != rejected.end() &&
                blocked->second.hash == hash &&
                GetTickCount64() < blocked->second.when)
              break;
            if (!token.empty() && token != rejected_session) {
              auto result = upload(*item, token);
              if (result == Result::Success) {
                if (image_rest_session() != token)
                  continue;
                if (acknowledged.size() >= cache_limit &&
                    acknowledged.find(identity) == acknowledged.end())
                  acknowledged.erase(acknowledged.begin());
                // A restart can retain its address and even restored tokens
                // while losing images. Revalidate later captures periodically.
                acknowledged[identity] = {hash, GetTickCount64()};
                rejected.erase(identity);
                break;
              }
              if (result == Result::Authentication)
                rejected_session = token;
              else if (result == Result::Permanent || ++failures >= 8) {
                if (rejected.size() >= cache_limit &&
                    rejected.find(identity) == rejected.end())
                  rejected.erase(rejected.begin());
                rejected[identity] = {
                    hash, GetTickCount64() +
                              (result == Result::Permanent ? 30000 : 5000)};
                break;
              }
            }
            if (WaitForSingleObject(stop_event.get(), token.empty() ? 250 : 1000)
                != WAIT_TIMEOUT)
              break;
          }
        }
      } catch (...) {
        note("image-sync-worker-failed");
      }
      item.reset();
      {
        std::lock_guard<std::mutex> lock(queue_lock);
        active = false;
      }
    }
  }
}
} // namespace
bool image_sync_transport() noexcept { return native_transport; }
bool install_image_sync(uintptr_t base) {
  return stage_hook((void *)(base + profile::image_reader), (void *)&image_hook,
                    (void **)&original_reader);
}
bool start_image_sync() {
  if (!config.content)
    return true;
  stop_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  work_event.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
  captures_idle.reset(CreateEventW(nullptr, TRUE, TRUE, nullptr));
  if (!stop_event || !work_event || !captures_idle)
    return false;
  worker.reset(CreateThread(nullptr, 0, image_worker, nullptr, 0, nullptr));
  return bool(worker);
}
void signal_image_sync_stop() noexcept {
  InterlockedExchange(&stopping, 1);
  if (stop_event)
    SetEvent(stop_event.get());
}
void stop_image_sync() noexcept {
  signal_image_sync_stop();
  if (!worker || WaitForSingleObject(worker.get(), 5000) == WAIT_OBJECT_0) {
    if (captures_idle &&
        WaitForSingleObject(captures_idle.get(), 5000) != WAIT_OBJECT_0)
      return;
    std::lock_guard<std::mutex> lock(queue_lock);
    if (capture_count)
      return;
    queue.clear();
    active = false;
    worker.reset();
    work_event.reset();
    stop_event.reset();
    captures_idle.reset();
  }
  // A timed-out worker still owns its handles. The DLL and activated hook
  // trampolines remain pinned; DllMain only signals and never joins.
}
#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) int WINAPI
WweNativeTestImageCapture(void *p, const void *expected) {
  Descriptor requested{};
  return guarded_read(expected, requested.data(), requested.size()) &&
         capture(p, requested);
}
extern "C" __declspec(dllexport) void WINAPI
WweNativeTestImageMutate(void (*fn)(void *)) { mutate_once = fn; }
extern "C" __declspec(dllexport) size_t WINAPI WweNativeTestImageBytes() {
  std::lock_guard<std::mutex> lock(queue_lock);
  return owned_bytes;
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestImageDrain() {
  auto start = GetTickCount64();
  while (GetTickCount64() - start < 15000) {
    {
      std::lock_guard<std::mutex> lock(queue_lock);
      if (queue.empty() && !active && !capture_count)
        return 1;
    }
    Sleep(10);
  }
  return 0;
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestImageStop() {
  stop_image_sync();
  return !worker && !work_event && !stop_event && !captures_idle;
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestImageStopping() {
  return InterlockedCompareExchange(&stopping, 0, 0) != 0;
}
extern "C" __declspec(dllexport) int WINAPI
WweNativeTestImageHook(void *target) {
  return stage_hook(target, (void *)&image_hook, (void **)&original_reader) &&
         MH_EnableHook(target) == MH_OK;
}
#endif
} // namespace wwe
