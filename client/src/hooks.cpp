#include "client.hpp"

#include "MinHook.h"
namespace wwe {
volatile LONG hooks_enabled = 0;
bool stage_hook(void *target, void *hook, void **original) {
  return target && MH_CreateHook(target, hook, original) == MH_OK;
}
} // namespace wwe

#ifdef WWE_OWNED_TEST
extern "C" __declspec(dllexport) void WINAPI WweNativeTestActive(int enabled) {
  InterlockedExchange(&wwe::hooks_enabled, enabled ? 1 : 0);
}
#endif
