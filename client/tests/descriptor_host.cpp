// Owned fixture: pure descriptor validation, no game/process/network access.
#include "../src/lobby_descriptor.hpp"
#include <cstdio>
#include <limits>
using namespace wwe::lobby_descriptor;
template <class T> void put(Bytes &data, size_t offset, T value) {
  std::memcpy(data.data() + offset, &value, sizeof(value));
}
int main() {
  constexpr uint64_t owner = 76561198000000001ULL;
  constexpr uint64_t lobby = 109212290963898369ULL;
  constexpr uint64_t match = 12345678901234567ULL;
  Bytes fixture{};
  put(fixture, 0, uint32_t(10));
  put(fixture, 4, uint32_t(size));
  put(fixture, 0x54, 0.31850001215934753f);
  put(fixture, 0x150, owner);
  put(fixture, 0x148, lobby);
  unsigned cases = 0;
  auto check = [&](bool condition) {
    ++cases;
    return condition;
  };
  if (!check(valid(fixture, owner, lobby, match)))
    return 1;
  if (!check(!valid(fixture, owner, lobby + 1, match)))
    return 2;
  if (!check(!valid(fixture, owner + 1, lobby, match)))
    return 3;
  if (!check(!valid(fixture, 0, lobby, match)))
    return 4;
  auto changed = fixture;
  put(changed, 0, uint32_t(9));
  if (!check(!valid(changed, owner, lobby, match)))
    return 5;
  changed = fixture;
  put(changed, 4, uint32_t(size - 1));
  if (!check(!valid(changed, owner, lobby, match)))
    return 6;
  changed = fixture;
  put(changed, 0x54, 0.0f);
  if (!check(!valid(changed, owner, lobby, match)))
    return 7;
  changed = fixture;
  put(changed, 0x54, std::numeric_limits<float>::quiet_NaN());
  if (!check(!valid(changed, owner, lobby, match)))
    return 8;
  changed = fixture;
  put(changed, 0x54, std::numeric_limits<float>::infinity());
  if (!check(!valid(changed, owner, lobby, match)))
    return 9;
  changed = fixture;
  put(changed, 0x148, uint64_t(0));
  put(changed, 0x248, match);
  if (!check(valid(changed, owner, lobby, match)))
    return 10;
  changed = fixture;
  put(changed, 0x148, uint64_t(0));
  if (!check(!valid(changed, owner, lobby, match)))
    return 11;
  if (!check(hex(fixture).size() == 1216 &&
             hex(fixture).substr(0, 16) == "0a00000060020000"))
    return 12;
  auto output = hex(fixture);
  bool same = true;
  for (size_t i = 0; i < fixture.size(); ++i) {
    auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    same =
        same && static_cast<unsigned>((digit(output[i * 2]) << 4) |
                                      digit(output[i * 2 + 1])) == fixture[i];
  }
  if (!check(same))
    return 13;
  std::printf("{\"descriptor_cases_passed\":%u}\n", cases);
  return 0;
}
