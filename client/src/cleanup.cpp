#include "client.hpp"
#include "profile.hpp"
#include <vector>
namespace wwe {
namespace {
void *cleanup_original = nullptr;
void *cleanup_code = nullptr;
} // namespace
void release_staged_cleanup() noexcept {
  if (cleanup_code) {
    VirtualFree(cleanup_code, 0, MEM_RELEASE);
    cleanup_code = nullptr;
  }
}
bool install_cleanup(uintptr_t base, uintptr_t directory_override) {
  auto entry = (unsigned char *)(base + profile::thread_cleanup);
  unsigned char actual[26]{};
  const unsigned char first[] = {0x40, 0x53, 0x48, 0x83,
                                 0xec, 0x20, 0x8b, 0x0d};
  const unsigned char tail[] = {0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0,
                                0,    0,    0xba, 0x38, 1,    0,    0};
  int32_t displacement = 0;
  if (!read_memory(entry, actual, sizeof(actual)) || memcmp(actual, first, 8) ||
      memcmp(actual + 12, tail, 14))
    return false;
  memcpy(&displacement, actual + 8, 4);
  if ((uintptr_t)entry + 12 + displacement != base + profile::tls_index)
    return false;
  cleanup_code =
      VirtualAlloc(nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!cleanup_code)
    return false;
  // Scratch RAX/RCX and flags are restored before either return or trampoline.
  std::vector<unsigned char> code = {0x9c, 0x50, 0x51};
  std::vector<size_t> jumps;
  auto bytes = [&](std::initializer_list<unsigned char> b) {
    code.insert(code.end(), b);
  };
  auto pointer = [&](uintptr_t p) {
    for (int i = 0; i < 8; ++i)
      code.push_back((unsigned char)(p >> (8 * i)));
  };
  auto jump_if = [&](unsigned char cc) {
    bytes({0x0f, cc});
    jumps.push_back(code.size());
    bytes({0, 0, 0, 0});
  };
  bytes({0x48, 0xb8});
  pointer((uintptr_t)&hooks_enabled);
  bytes({0x83, 0x38, 0});
  jump_if(0x84);
  bytes({0x48, 0xb8});
  pointer(base + profile::thread_system);
  bytes({0x48, 0x83, 0x38, 0});
  jump_if(0x85);
  if (directory_override) {
    bytes({0x48, 0xb8});
    pointer(directory_override);
    bytes({0x48, 0x8b, 0x00});
  } else
    bytes({0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0, 0, 0});
  bytes({0x48, 0x85, 0xc0});
  jump_if(0x84);
  bytes({0x48, 0xb9});
  pointer(base + profile::tls_index);
  bytes({0x8b, 0x09, 0x48, 0x8b, 0x04, 0xc8, 0x48, 0x85, 0xc0});
  jump_if(0x84);
  bytes({0x48, 0x83, 0xb8, 0x38, 1, 0, 0, 0});
  jump_if(0x85);
  bytes({0x59, 0x58, 0x9d, 0xc3});
  size_t fallback = code.size();
  bytes({0x59, 0x58, 0x9d, 0xff, 0x25, 0, 0, 0, 0});
  size_t target = code.size();
  pointer(0);
  DWORD preparation = 0;
  if (!VirtualProtect(cleanup_code, 256, PAGE_EXECUTE_READ, &preparation) ||
      !stage_hook(entry, cleanup_code, &cleanup_original))
    return false;
  if (!VirtualProtect(cleanup_code, 256, PAGE_READWRITE, &preparation))
    return false;
  for (auto pos : jumps) {
    int32_t rel = (int32_t)(fallback - pos - 4);
    memcpy(code.data() + pos, &rel, 4);
  }
  memcpy(code.data() + target, &cleanup_original, 8);
  memcpy(cleanup_code, code.data(), code.size());
  DWORD old = 0;
  if (!VirtualProtect(cleanup_code, 256, PAGE_EXECUTE_READ, &old))
    return false;
  FlushInstructionCache(GetCurrentProcess(), cleanup_code, code.size());
  return true;
}
} // namespace wwe
