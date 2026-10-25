#include "resources.hpp"
#include <bcrypt.h>
#include <vector>
namespace wwe {
bool digest_matches(const std::wstring &path, const char *expected) {
  KernelHandle file(CreateFileW(
      path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (!file)
    return false;
  struct Provider {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Provider() {
      if (value)
        BCryptCloseAlgorithmProvider(value, 0);
    }
  } provider;
  std::vector<unsigned char> object;
  struct Hash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() {
      if (value)
        BCryptDestroyHash(value);
    }
  } digest;
  auto &algorithm = provider.value;
  auto &hash = digest.value;
  DWORD size = 0, used = 0;
  bool okay = false;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) >= 0 &&
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&size,
                        sizeof(size), &used, 0) >= 0) {
    object.resize(size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), size, nullptr, 0,
                         0) >= 0) {
      unsigned char buffer[65536], result[32];
      DWORD count;
      okay = true;
      for (;;) {
        if (!ReadFile(file.get(), buffer, sizeof(buffer), &count, nullptr)) {
          okay = false;
          break;
        }
        if (!count)
          break;
        if (BCryptHashData(hash, buffer, count, 0) < 0) {
          okay = false;
          break;
        }
      }
      if (okay && BCryptFinishHash(hash, result, 32, 0) >= 0) {
        const char hex[] = "0123456789abcdef";
        std::string got;
        for (auto ch : result) {
          got += hex[ch >> 4];
          got += hex[ch & 15];
        }
        okay = got == expected;
      } else
        okay = false;
      BCryptDestroyHash(hash);
      hash = nullptr;
    }
  }

  return okay;
}

} // namespace wwe
