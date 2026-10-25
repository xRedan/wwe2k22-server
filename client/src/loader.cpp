// Process-lifetime DirectInput proxy; all heavy work is outside DllMain.
#define DIRECTINPUT_VERSION 0x0800
#include "client.hpp"

#include "MinHook.h"
#include <dinput.h>
#ifndef WWE_TARGET_SHA256
#error A verified target digest is required
#endif
using namespace wwe;
static HMODULE self_module = nullptr, real_input = nullptr;
static INIT_ONCE start_once = INIT_ONCE_STATIC_INIT,
                 input_once = INIT_ONCE_STATIC_INIT;
enum StartupState : LONG { Pending = 0, Ready = 1, Disabled = 2, Failed = -1 };
static volatile LONG initialized = Pending;
static decltype(&WinHttpOpen) original_open = nullptr;
static BOOL CALLBACK initialize(PINIT_ONCE, void *, void **) {
  bool activation_attempted = false;
  try {
    auto folder = directory(module_path(self_module));
    if (folder.empty())
      throw 1;
    initialize_log(folder);
    config = load_config(folder);
    if (!config.enabled) {
      InterlockedExchange(&initialized, Disabled);
      note("disabled");
      return TRUE;
    }
    if (!digest_matches(module_path(nullptr), WWE_TARGET_SHA256)) {
      note("target-digest-mismatch");
      InterlockedExchange(&initialized, Failed);
      return TRUE;
    }
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_PIN,
                            (LPCWSTR)&initialize, &pinned))
      throw 1;
    // Allocate all mandatory resources before enabling any hook.
    if (!start_publication() || MH_Initialize() != MH_OK || !install_http() ||
        !install_game() || MH_QueueEnableHook(MH_ALL_HOOKS) != MH_OK)
      throw 1;
    activation_attempted = true;
    if (MH_ApplyQueued() != MH_OK)
      throw 1;
#ifdef WWE_OWNED_TEST
    if (GetEnvironmentVariableW(L"WWE_OWNED_FAIL_AFTER_APPLY", nullptr, 0))
      throw 1;
#endif
    InterlockedExchange(&hooks_enabled, 1);
    if (!start_diagnostics(folder))
      note("crash-log-unavailable");
    InterlockedExchange(&initialized, Ready);
    note("native-client-ready");
  } catch (...) {
    InterlockedExchange(&hooks_enabled, 0);
    MH_DisableHook(MH_ALL_HOOKS);
    if (!activation_attempted) {
      MH_RemoveHook(MH_ALL_HOOKS);
      release_staged_cleanup();
      MH_Uninitialize();
    }
    // A detour may already be in flight after an activation attempt. Keep its
    // trampoline/code pinned, even on failure, rather than freeing live code.
    stop_publication();
    note("configuration-or-start-failed");
    InterlockedExchange(&initialized, Failed);
  }
  return TRUE;
}
static HINTERNET WINAPI gated_open(LPCWSTR agent, DWORD access, LPCWSTR proxy,
                                   LPCWSTR bypass, DWORD flags) {
  DWORD before = GetLastError();
  InitOnceExecuteOnce(&start_once, initialize, nullptr, nullptr);
  LONG state = InterlockedCompareExchange(&initialized, 0, 0);
  if ((state != Ready && state != Disabled) || !original_open) {
    SetLastError(ERROR_INVALID_DATA);
    return nullptr;
  }
  SetLastError(before);
  return original_open(agent, access, proxy, bypass, flags);
}
static bool gate_first_http() {
  // Loader calls this before main(). Only inspect mapped headers and replace
  // one IAT pointer; no file I/O, LoadLibrary, hashing, wait or worker in
  // DllMain.
  auto base = (unsigned char *)GetModuleHandleW(nullptr);
  auto dos = (IMAGE_DOS_HEADER *)base;
  if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE)
    return false;
  auto nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return false;
  auto imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!imports.VirtualAddress)
    return false;
  auto descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(base + imports.VirtualAddress);
  for (; descriptor->Name; descriptor++) {
    if (_stricmp((char *)(base + descriptor->Name), "winhttp.dll"))
      continue;
    if (!descriptor->OriginalFirstThunk)
      return false;
    auto names = (IMAGE_THUNK_DATA64 *)(base + descriptor->OriginalFirstThunk);
    auto slots = (IMAGE_THUNK_DATA64 *)(base + descriptor->FirstThunk);
    for (; names->u1.AddressOfData; names++, slots++) {
      if (IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal))
        continue;
      auto name = (IMAGE_IMPORT_BY_NAME *)(base + names->u1.AddressOfData);
      if (strcmp((char *)name->Name, "WinHttpOpen"))
        continue;
      DWORD previous;
      if (!VirtualProtect(&slots->u1.Function, sizeof(void *), PAGE_READWRITE,
                          &previous))
        return false;
      original_open = (decltype(original_open))InterlockedExchangePointer(
          (PVOID volatile *)&slots->u1.Function, (PVOID)gated_open);
      DWORD ignored;
      VirtualProtect(&slots->u1.Function, sizeof(void *), previous, &ignored);
      return original_open != nullptr;
    }
  }
  return false;
}
static BOOL CALLBACK load_input(PINIT_ONCE, void *, void **) {
  wchar_t path[32768];
  UINT n = GetSystemDirectoryW(path, 32768);
  if (!n || n > 32740)
    return TRUE;
  wcscat_s(path, 32768, L"\\dinput8.dll");
  real_input = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  return TRUE;
}
template <typename T> static T input_function(const char *name) {
  InitOnceExecuteOnce(&input_once, load_input, nullptr, nullptr);
  return real_input ? (T)GetProcAddress(real_input, name) : nullptr;
}
extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE instance, DWORD version,
                                             REFIID iid, LPVOID *out,
                                             LPUNKNOWN outer) {
  auto fn = input_function<decltype(&DirectInput8Create)>("DirectInput8Create");
  return fn ? fn(instance, version, iid, out, outer) : E_FAIL;
}
extern "C" HRESULT WINAPI DllCanUnloadNow() {
  auto fn = input_function<HRESULT(WINAPI *)()>("DllCanUnloadNow");
  return fn ? fn() : S_FALSE;
}
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID cls, REFIID iid,
                                            void **out) {
  auto fn = input_function<HRESULT(WINAPI *)(REFCLSID, REFIID, void **)>(
      "DllGetClassObject");
  return fn ? fn(cls, iid, out) : E_FAIL;
}
extern "C" HRESULT WINAPI DllRegisterServer() {
  auto fn = input_function<HRESULT(WINAPI *)()>("DllRegisterServer");
  return fn ? fn() : E_FAIL;
}
extern "C" HRESULT WINAPI DllUnregisterServer() {
  auto fn = input_function<HRESULT(WINAPI *)()>("DllUnregisterServer");
  return fn ? fn() : E_FAIL;
}
extern "C" LPCDIDATAFORMAT WINAPI GetdfDIJoystick() {
  auto fn = input_function<LPCDIDATAFORMAT(WINAPI *)()>("GetdfDIJoystick");
  return fn ? fn() : nullptr;
}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *) {
  if (reason == DLL_PROCESS_ATTACH) {
    self_module = module;
    if (!gate_first_http())
      return FALSE;
  }
  // Process-lifetime dependency: never wait for workers while holding loader
  // lock.
  if (reason == DLL_PROCESS_DETACH) {
    signal_publication_stop();
  }
  return TRUE;
}
