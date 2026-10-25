#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
namespace wwe::lobby_descriptor {
inline constexpr size_t size = 0x260;
using Bytes = std::array<unsigned char, size>;
inline bool contains_id(const Bytes &data, uint64_t id) noexcept {
  if (!id)
    return false;
  std::array<unsigned char, 8> bytes{};
  for (size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<unsigned char>(id >> (i * 8));
  return std::search(data.begin(), data.end(), bytes.begin(), bytes.end()) !=
         data.end();
}
inline bool valid(const Bytes &data, uint64_t owner, uint64_t lobby,
                  uint64_t match) noexcept {
  uint32_t version = 0, length = 0;
  uint64_t actual_owner = 0;
  float marker = 0;
  std::memcpy(&version, data.data(), sizeof(version));
  std::memcpy(&length, data.data() + 4, sizeof(length));
  std::memcpy(&marker, data.data() + 0x54, sizeof(marker));
  std::memcpy(&actual_owner, data.data() + 0x150, sizeof(actual_owner));
  // Do not reuse a cached descriptor from another room. Its exact ID offset
  // is not assumed: require a literal current Steam lobby or native match ID.
  return version == 10 && length == size && owner && actual_owner == owner &&
         std::isfinite(marker) && marker != 0 &&
         (contains_id(data, lobby) || contains_id(data, match));
}
inline std::string hex(const Bytes &data) {
  constexpr char digits[] = "0123456789abcdef";
  std::string output(data.size() * 2, '0');
  for (size_t i = 0; i < data.size(); ++i) {
    output[i * 2] = digits[data[i] >> 4];
    output[i * 2 + 1] = digits[data[i] & 15];
  }
  return output;
}
} // namespace wwe::lobby_descriptor
