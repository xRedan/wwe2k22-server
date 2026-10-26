#include "resources.hpp"

#include "MinHook.h"
#include "lobby_descriptor.hpp"
#include "profile.hpp"
#include <array>
#include <atomic>
#include <map>
#include <mutex>
#include <string_view>
namespace wwe {
namespace {
uintptr_t base = 0;
void *matchmaking = nullptr;
using ContextInit = void *(*)(void *);
using RunCallbacks = void (*)();
using SessionReader = void *(*)(void *, void *);
ContextInit original_context = nullptr;
RunCallbacks original_callbacks = nullptr;
SessionReader original_session = nullptr;
void *(*getter)() = nullptr;
using SetType = bool (*)(void *, uint64_t, int);
using SetJoinable = bool (*)(void *, uint64_t, bool);
SetType original_type = nullptr;
SetJoinable original_joinable = nullptr;
struct Observation {
  int type = -1;
  bool closed = false;
};
std::map<uint64_t, Observation> observations;
void *type_target = nullptr;
void *join_target = nullptr;
bool interface_warning = false;
bool descriptor_warning = false;
uint64_t active = 0;
bool previous_private = false;
std::string published, signature;
ULONGLONG last_poll = 0, last_publish = 0;
std::recursive_mutex steam_state;
std::atomic<uint64_t> pending_session{0};
uint64_t committed_session = 0;
template <class T> T at(uintptr_t p) {
  T result{};
  read((void *)p, result);
  return result;
}
template <class T> T method(void *instance, size_t offset) {
  auto table = at<uintptr_t>((uintptr_t)instance);
  return (T)at<uintptr_t>(table + offset);
}
bool executable(void *ptr) {
  MEMORY_BASIC_INFORMATION m{};
  return ptr && VirtualQuery(ptr, &m, sizeof(m)) && m.State == MEM_COMMIT &&
         !(m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
         (m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}
void withdraw() {
  if (!published.empty()) {
    if (enqueue(PublicationAction::Withdraw, published)) {
      published.clear();
      signature.clear();
      last_publish = 0;
    }
  }
}
void trim(uint64_t current) {
  if (observations.size() <= 128)
    return;
  for (auto it = observations.begin(); it != observations.end(); ++it)
    if (it->first != active && it->first != current) {
      observations.erase(it);
      break;
    }
}
bool type_hook(void *self, uint64_t lobby, int type) {
  bool result = original_type(self, lobby, type);
  PreserveLastError error;
  try {
    std::lock_guard<std::recursive_mutex> lock(steam_state);
    if (hooks_ready() && result && self == matchmaking) {
      observations[lobby].type = type;
      trim(lobby);
      if (type != 2) {
        if (lobby == active) {
          auto manager = at<uintptr_t>(base + profile::lobby_manager);
          if (manager && at<uint8_t>(manager + profile::lobby_private))
            previous_private = true;
          withdraw();
        }
      }
    }
  } catch (...) {
    note("steam-observer-failed");
  }
  return result;
}
bool joinable_hook(void *self, uint64_t lobby, bool enabled) {
  bool result = original_joinable(self, lobby, enabled);
  PreserveLastError error;
  try {
    std::lock_guard<std::recursive_mutex> lock(steam_state);
    if (hooks_ready() && result && self == matchmaking) {
      observations[lobby].closed = !enabled;
      trim(lobby);
      if (!enabled && lobby == active)
        withdraw();
    }
  } catch (...) {
    note("steam-observer-failed");
  }
  return result;
}
void bind(void *instance) {
  std::lock_guard<std::recursive_mutex> lock(steam_state);
  if (!instance || instance == matchmaking)
    return;
  auto t = method<SetType>(instance, profile::set_type_slot);
  auto j = method<SetJoinable>(instance, profile::set_joinable_slot);
  for (size_t slot : {profile::owner_slot, profile::metadata_count_slot,
                      profile::metadata_item_slot, profile::members_slot,
                      profile::member_limit_slot, profile::set_type_slot,
                      profile::set_joinable_slot})
    if (!executable(method<void *>(instance, slot)))
      return;
  if (type_target) {
    // Reuse existing trampolines when Steam supplies a replacement context.
    if (type_target != (void *)t || join_target != (void *)j) {
      withdraw();
      matchmaking = nullptr;
      active = 0;
      observations.clear();
      previous_private = false;
      if (!interface_warning) {
        note("steam-interface-changed");
        interface_warning = true;
      }
      return;
    }
  } else {
    if (!stage_hook((void *)t, (void *)&type_hook, (void **)&original_type))
      return;
    if (!stage_hook((void *)j, (void *)&joinable_hook,
                    (void **)&original_joinable)) {
      MH_RemoveHook((void *)t);
      return;
    }
    type_target = (void *)t;
    join_target = (void *)j;
  }
  if (MH_QueueEnableHook((void *)t) != MH_OK ||
      MH_QueueEnableHook((void *)j) != MH_OK || MH_ApplyQueued() != MH_OK) {
    MH_DisableHook((void *)t);
    MH_DisableHook((void *)j);
    // Keep created trampolines: an observer may already be returning through
    // one.
    note("steam-observer-install-failed");
    return;
  }
  if (matchmaking && matchmaking != instance) {
    withdraw();
    observations.clear();
    active = 0;
    previous_private = false;
  }
  matchmaking = instance;
}
void *context_hook(void *selector) {
  void *result = original_context(selector);
  PreserveLastError error;
  try {
    if (hooks_ready() && config.lobbies &&
        (uintptr_t)selector == base + profile::matchmaking_selector)
      bind(at<void *>((uintptr_t)result));
  } catch (...) {
    note("steam-observer-failed");
  }
  return result;
}
void callbacks_hook() {
  original_callbacks();
  PreserveLastError error;
  try {
    std::lock_guard<std::recursive_mutex> lock(steam_state);
    if (hooks_ready() && config.lobbies) {
      if (!matchmaking && getter)
        bind(getter());
      poll_lobby();
    }
  } catch (...) {
    note("steam-observer-failed");
  }
}
void *session_hook(void *object, void *result) {
  void *returned = original_session(object, result);
  PreserveLastError error;
  if (hooks_ready())
    observe_session(object, result);
  return returned;
}
struct LobbySnapshot {
  uintptr_t manager = 0;
  uint32_t active = 0;
  uint64_t lobby = 0, own = 0, match = 0;
  uint8_t private_room = 0;
};
bool capture_lobby(LobbySnapshot &value) {
  return read((void *)(base + profile::lobby_manager), value.manager) &&
         value.manager &&
         read((void *)(value.manager + profile::lobby_active), value.active) &&
         value.active &&
         read((void *)(value.manager + profile::lobby_id), value.lobby) &&
         read((void *)(value.manager + profile::own_steam_id), value.own) &&
         read((void *)(base + profile::current_match), value.match) &&
         value.match &&
         read((void *)(value.manager + profile::lobby_private),
              value.private_room);
}
bool capture_descriptor(const LobbySnapshot &expected, std::string &encoded) {
  lobby_descriptor::Bytes first{}, second{};
  if (!read_memory((void *)(base + profile::session_descriptor), first.data(),
                   first.size()) ||
      !lobby_descriptor::valid(first, expected.own, expected.lobby,
                               expected.match) ||
      !read_memory((void *)(base + profile::session_descriptor), second.data(),
                   second.size()) ||
      first != second)
    return false;
  LobbySnapshot current;
  if (!capture_lobby(current) || current.manager != expected.manager ||
      current.lobby != expected.lobby || current.match != expected.match ||
      current.own != expected.own || current.private_room)
    return false;
  encoded = lobby_descriptor::hex(first);
  return true;
}
bool allowed(const std::string &key) {
  constexpr std::array<std::string_view, 12> names = {
      "spec_dev",      "spec_fps",         "build_no",        "spec_pubOpen",
      "spec_privOpen", "spec_hostID",      "spec_vc_matchid", "spec_team",
      "spec_team_num", "spec_tagteamflag", "spec_voiceChat",  "spec_migrate"};
  for (auto name : names)
    if (key == name)
      return true;
  size_t begin = !key.empty() && key[0] == '-' ? 1 : 0;
  return key.size() > begin && key.size() - begin <= 10 &&
         key.find_first_not_of("0123456789", begin) == std::string::npos;
}
} // namespace
void observe_session(void *object, void *result) {
  uint32_t status = 0;
  uintptr_t response = 0;
  uint64_t key = 0;
  if (object && read(result, status) && status == 0x8a46d950 &&
      read((char *)object + 0xa8, response) && !response &&
      read((char *)object + 0xe8, key) && key)
    pending_session.store(key, std::memory_order_release);
}
void poll_lobby() {
  std::lock_guard<std::recursive_mutex> lock(steam_state);
  auto key = pending_session.load(std::memory_order_acquire);
  if (key && key != committed_session) {
    native_session(key);
    committed_session = key;
    published.clear();
    signature.clear();
    last_publish = 0;
  }
  auto now = GetTickCount64();
  if (last_poll && now - last_poll < 2000)
    return;
  last_poll = now;
  if (!matchmaking)
    return;
  for (size_t offset : {profile::owner_slot, profile::metadata_count_slot,
                        profile::metadata_item_slot, profile::members_slot,
                        profile::member_limit_slot})
    if (!executable(method<void *>(matchmaking, offset))) {
      withdraw();
      return;
    }
  LobbySnapshot native;
  if (!capture_lobby(native)) {
    withdraw();
    active = 0;
    previous_private = false;
    return;
  }
  const auto manager = native.manager;
  const auto lobby = native.lobby;
  auto high = (uint32_t)(lobby >> 32);
  if (!lobby || (high & 0xf00000) != 0x800000 || !(high & 0x40000)) {
    withdraw();
    return;
  }
  uint64_t owner = 0;
  auto owner_fn = method<void *(*)(void *, uint64_t *, uint64_t)>(
      matchmaking, profile::owner_slot);
  owner_fn(matchmaking, &owner, lobby);
  if (!owner || owner != native.own) {
    withdraw();
    return;
  }
  bool priv = native.private_room != 0;
  if (active != lobby || previous_private) {
    if (!priv) {
      auto entry = observations.find(lobby);
      if (entry != observations.end())
        entry->second.type = -1;
    }
  }
  if (active != lobby)
    descriptor_warning = false;
  active = lobby;
  previous_private = priv;
  auto observed = observations.find(lobby);
  if (priv || (observed != observations.end() &&
               (observed->second.closed ||
                (observed->second.type >= 0 && observed->second.type != 2)))) {
    withdraw();
    return;
  }
  int count = method<int (*)(void *, uint64_t)>(
      matchmaking, profile::metadata_count_slot)(matchmaking, lobby);
  if (count < 1 || count > 128) {
    withdraw();
    return;
  }
  std::map<std::string, std::string> metadata;
  for (int i = 0; i < count; ++i) {
    std::array<char, 64> k{};
    std::array<char, 256> v{};
    bool ok = method<bool (*)(void *, uint64_t, int, char *, int, char *, int)>(
        matchmaking, profile::metadata_item_slot)(matchmaking, lobby, i,
                                                  k.data(), (int)k.size(),
                                                  v.data(), (int)v.size());
    if (ok) {
      auto name = ascii(k.data(), k.size());
      auto value = ascii(v.data(), v.size());
      if (!name.empty() && allowed(name))
        metadata[name] = value;
    }
  }
  auto match = metadata["spec_vc_matchid"];
  auto host = metadata["spec_hostID"];
  auto slots = metadata["spec_pubOpen"];
  if (match != std::to_string(native.match) || host != std::to_string(owner) ||
      slots.empty() || slots.size() > 3 ||
      slots.find_first_not_of("0123456789") != std::string::npos ||
      slots.find_first_not_of("0") == std::string::npos) {
    withdraw();
    return;
  }
  int limit = method<int (*)(void *, uint64_t)>(
      matchmaking, profile::member_limit_slot)(matchmaking, lobby);
  int members = method<int (*)(void *, uint64_t)>(
      matchmaking, profile::members_slot)(matchmaking, lobby);
  if (limit < 1 || limit > 100 || members < 0 || members > limit) {
    withdraw();
    return;
  }
  if (observed == observations.end() || observed->second.type != 2) {
    // Call the saved trampoline; the observer records external changes only.
    bool ok = original_type(matchmaking, lobby, 2);
    uint8_t private_room = 0;
    if (!ok ||
        !read((void *)(manager + profile::lobby_private), private_room) ||
        private_room) {
      withdraw();
      return;
    }
    observations[lobby].type = 2;
    trim(lobby);
  }
  std::string identity = "{\"lobby_id\":" + quote(std::to_string(lobby)) +
                         ",\"match_id\":" + quote(match) + "}";
  std::string body = "{\"lobby_id\":" + quote(std::to_string(lobby)) +
                     ",\"match_id\":" + quote(match) + ",\"metadata\":{";
  bool first = true;
  for (const auto &item : metadata) {
    if (!first)
      body += ',';
    first = false;
    body += quote(item.first) + ":" + quote(item.second);
  }
  body += "},\"visibility\":\"public\",\"joinable\":true,\"member_limit\":" +
          std::to_string(limit) +
          ",\"member_count\":" + std::to_string(members);
  std::string descriptor;
  if (capture_descriptor(native, descriptor)) {
    body += ",\"native_descriptor\":" + quote(descriptor);
    descriptor_warning = false;
  } else if (!descriptor_warning) {
    note("lobby-descriptor-unavailable");
    descriptor_warning = true;
  }
  body += "}";
  if (!published.empty() && published != identity) {
    withdraw();
    if (!published.empty())
      return;
  }
  if (published.empty() || signature != body || now - last_publish >= 30000) {
    if (enqueue(PublicationAction::Publish, body)) {
      published = identity;
      signature = body;
      last_publish = now;
    }
  }
}
extern "C" void *wwe_cdn_original = nullptr;
extern "C" void wwe_cdn_gateway();
extern "C" void wwe_cdn_observe(uintptr_t stack) noexcept {
  try {
    if (!hooks_ready())
      return;
    auto text = at<void *>(stack + 0x58);
    auto url = ascii(text, 512);
    if (!url.empty())
      learn_cdn(url);
  } catch (...) {
    note("cdn-observer-failed");
  }
}
bool install_game() {
#ifdef WWE_OWNED_TEST
  return GetEnvironmentVariableW(L"WWE_OWNED_FAIL_START", nullptr, 0) == 0;
#else
  base = (uintptr_t)GetModuleHandleW(nullptr);
  HMODULE steam =
      config.lobbies ? GetModuleHandleW(L"steam_api64.dll") : nullptr;
  if (config.lobbies && !steam)
    return false;
  if (config.content &&
      (!stage_hook((void *)(base + profile::cdn_initializer),
                   (void *)&wwe_cdn_gateway, &wwe_cdn_original) ||
       !install_image_sync(base)))
    return false;
  if (config.lobbies) {
    if (!install_lobby_search(base))
      return false;
    getter =
        (void *(*)())GetProcAddress(steam, "SteamAPI_SteamMatchmaking_v009");
    if (!stage_hook((void *)GetProcAddress(steam, "SteamInternal_ContextInit"),
                    (void *)&context_hook, (void **)&original_context) ||
        !stage_hook((void *)GetProcAddress(steam, "SteamAPI_RunCallbacks"),
                    (void *)&callbacks_hook, (void **)&original_callbacks) ||
        !stage_hook((void *)(base + profile::session_reader),
                    (void *)&session_hook, (void **)&original_session))
      return false;
  }
  if (config.guard && !install_cleanup(base))
    return false;
  return true;
#endif
}
} // namespace wwe

#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) int WINAPI WweNativeTestGateway(void *target) {
  return wwe::stage_hook(target, (void *)&wwe::wwe_cdn_gateway,
                         &wwe::wwe_cdn_original) &&
         MH_EnableHook(target) == MH_OK;
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestBind(void *arena,
                                                              void *instance) {
  wwe::base = (uintptr_t)arena;
  wwe::bind(instance);
  return wwe::matchmaking == instance;
}
extern "C" __declspec(dllexport) int WINAPI WweNativeTestPoll() {
  wwe::last_poll = 0;
  wwe::poll_lobby();
  return (wwe::published.empty() ? 0 : 1) | (wwe::previous_private ? 2 : 0) |
         (wwe::observations.count(wwe::active) &&
                  wwe::observations.at(wwe::active).type >= 0
              ? 4
              : 0);
}
extern "C" __declspec(dllexport) void *WINAPI
WweNativeTestReader(void *fn, void *object, void *result) {
  wwe::original_session = (wwe::SessionReader)fn;
  return wwe::session_hook(object, result);
}
#endif

#ifdef WWE_OWNED_TEST
extern "C"
    __declspec(dllexport) int WINAPI WweNativeTestGuard(void *arena,
                                                        void *directory) {
  wwe::base = (uintptr_t)arena;
  return wwe::install_cleanup(wwe::base, (uintptr_t)directory) &&
         MH_EnableHook((void *)(wwe::base + wwe::profile::thread_cleanup)) ==
             MH_OK;
}
#endif

#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) void
    WINAPI WweNativeTestObserveSession(void *object, void *result) {
  wwe::observe_session(object, result);
}
#endif
