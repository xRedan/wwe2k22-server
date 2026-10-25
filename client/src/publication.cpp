#include "resources.hpp"
#include <deque>
#include <mutex>
namespace wwe {
namespace {
struct Work {
  PublicationAction action;
  std::string body;
  uint64_t session;
};
std::mutex queue_mutex;
std::deque<Work> queue;
uint64_t session_id = 0;
KernelHandle work_event, worker;
volatile LONG stopping = 0;
#ifdef WWE_OWNED_TEST
bool work_active = false;
#endif
enum class WorkResult { Skipped, Complete, Retryable };
WorkResult perform_work(Work &work, bool retry) {
  {
    std::lock_guard<std::mutex> lock(queue_mutex);
    if ((retry && !queue.empty()) || work.session != session_id ||
        InterlockedCompareExchange(&stopping, 0, 0))
      return WorkResult::Skipped;
  }
  InternetHandle session(WinHttpOpen(L"WWE2K22-native-client",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr,
                                     nullptr, 0));
  if (!session || !WinHttpSetTimeouts(session.get(), 3000, 3000, 3000, 3000)) {
    note("publication-failed");
    return WorkResult::Retryable;
  }
  InternetHandle connection(
      WinHttpConnect(session.get(), config.host.c_str(), config.port, 0));
  if (!connection) {
    note("publication-failed");
    return WorkResult::Retryable;
  }
  const wchar_t *path = work.action == PublicationAction::Publish
                            ? L"/lab/lobbies/publish"
                            : L"/lab/lobbies/withdraw";
  InternetHandle request(WinHttpOpenRequest(
      connection.get(), L"POST", path, nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, config.https ? WINHTTP_FLAG_SECURE : 0));
  if (!request) {
    note("publication-failed");
    return WorkResult::Retryable;
  }
  DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
                        &redirect_policy, sizeof(redirect_policy))) {
    note("publication-failed");
    return WorkResult::Retryable;
  }
  if (!config.key_header.empty() &&
      !WinHttpAddRequestHeaders(
          request.get(), config.key_header.c_str(), (DWORD)-1,
          WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
    note("publication-failed");
    return WorkResult::Retryable;
  }
  std::wstring headers = L"Content-Type: application/json\r\nS: " +
                         std::to_wstring(work.session) + L"\r\n";
  {
    std::lock_guard<std::mutex> lock(queue_mutex);
    if ((retry && !queue.empty()) || work.session != session_id ||
        InterlockedCompareExchange(&stopping, 0, 0))
      return WorkResult::Skipped;
  }
  BOOL sent = WinHttpSendRequest(request.get(), headers.c_str(), (DWORD)-1,
                                 work.body.data(), (DWORD)work.body.size(),
                                 (DWORD)work.body.size(), 0) &&
              WinHttpReceiveResponse(request.get(), nullptr);
  DWORD status = 0, size = sizeof(status);
  if (sent)
    WinHttpQueryHeaders(request.get(),
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &status, &size, nullptr);
  note(work.action == PublicationAction::Publish ? "publication-result"
                                                 : "withdraw-result",
       (int)status);
  return status == 0 || status == 500 || status == 502 || status == 503 ||
                 status == 504
             ? WorkResult::Retryable
             : WorkResult::Complete;
}
DWORD WINAPI publish_worker(void *) {
  for (;;) {
    if (WaitForSingleObject(work_event.get(), INFINITE) != WAIT_OBJECT_0)
      break;
    for (;;) {
      std::unique_lock<std::mutex> lock(queue_mutex);
      if (InterlockedCompareExchange(&stopping, 0, 0))
        return 0;
      if (queue.empty()) {
        ResetEvent(work_event.get());
        break;
      }
      Work work = std::move(queue.front());
      queue.pop_front();
#ifdef WWE_OWNED_TEST
      work_active = true;
#endif
      lock.unlock();
      try {
        // At most three attempts. Newer work (especially a withdrawal) or a
        // rotated session cancels retries; never replay obsolete room data.
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
          if (perform_work(work, attempt != 0) != WorkResult::Retryable ||
              attempt == 2)
            break;
          Sleep(attempt == 0 ? 250 : 750);
          std::lock_guard<std::mutex> retry_lock(queue_mutex);
          if (!queue.empty() || work.session != session_id ||
              InterlockedCompareExchange(&stopping, 0, 0))
            break;
        }
      } catch (...) {
        note("publication-worker-failed");
      }
#ifdef WWE_OWNED_TEST
      lock.lock();
      work_active = false;
#endif
    }
  }
  return 0;
}
} // namespace
bool start_publication() {
  if (!config.lobbies)
    return true;
  work_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!work_event)
    return false;
  worker.reset(CreateThread(nullptr, 0, publish_worker, nullptr, 0, nullptr));
  if (!worker) {
    work_event.reset();
    return false;
  }
  return true;
}
void signal_publication_stop() noexcept {
  InterlockedExchange(&stopping, 1);
  if (work_event)
    SetEvent(work_event.get());
}
void stop_publication() noexcept {
  signal_publication_stop();
  if (!worker || WaitForSingleObject(worker.get(), 5000) == WAIT_OBJECT_0) {
    worker.reset();
    work_event.reset();
  }
  // Never free resources belonging to a thread that has not completed.
}
void native_session(uint64_t id) {
  if (!id || !config.lobbies)
    return;
  std::lock_guard<std::mutex> lock(queue_mutex);
  if (id != session_id) {
    session_id = id;
    queue.clear();
  }
}
uint64_t publication_session() {
  std::lock_guard<std::mutex> lock(queue_mutex);
  return session_id;
}
bool enqueue(PublicationAction action, const std::string &body) {
  if (!config.lobbies || body.empty() || body.size() > 65536 ||
      (action != PublicationAction::Publish &&
       action != PublicationAction::Withdraw))
    return false;
  {
    std::lock_guard<std::mutex> lock(queue_mutex);
    if (!worker || !session_id || queue.size() >= 16 ||
        InterlockedCompareExchange(&stopping, 0, 0))
      return false;
    queue.push_back({action, body, session_id});
  }
  SetEvent(work_event.get());
  return true;
}
#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) int WINAPI WweNativeTestWorkerStopped() {
  return !worker && !work_event;
}
extern "C" __declspec(dllexport) void WINAPI WweNativeTestSession(uint64_t id) {
  native_session(id);
}
extern "C" __declspec(dllexport) int WINAPI
WweNativeTestQueue(const char *action, const char *body) {
  if (!action || !body)
    return 0;
  size_t length = strnlen(body, 65537);
  std::string name(action, strnlen(action, 9));
  if (length > 65536 || (name != "publish" && name != "withdraw"))
    return 0;
  return enqueue(name == "publish" ? PublicationAction::Publish
                                   : PublicationAction::Withdraw,
                 std::string(body, length));
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestDrain() {
  auto start = GetTickCount64();
  while (GetTickCount64() - start < 10000) {
    bool done = false;
    {
      std::lock_guard<std::mutex> lock(queue_mutex);
      done = queue.empty() && !work_active;
    }
    if (done)
      return 1;
    Sleep(10);
  }
  return 0;
}
#endif
} // namespace wwe
