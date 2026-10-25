#pragma once
#include "client.hpp"
#include <utility>
namespace wwe {
// Ownership is explicit; each Win32/WinHTTP handle is closed exactly once.
struct KernelHandleTraits {
  static void close(HANDLE h) noexcept { CloseHandle(h); }
};
struct InternetHandleTraits {
  static void close(HANDLE h) noexcept { WinHttpCloseHandle(h); }
};
template <class Traits> class UniqueHandle {
  HANDLE value_ = nullptr;

public:
  explicit UniqueHandle(HANDLE value = nullptr) noexcept : value_(value) {}
  ~UniqueHandle() { reset(); }
  UniqueHandle(const UniqueHandle &) = delete;
  UniqueHandle &operator=(const UniqueHandle &) = delete;
  UniqueHandle(UniqueHandle &&other) noexcept : value_(other.release()) {}
  UniqueHandle &operator=(UniqueHandle &&other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  HANDLE get() const noexcept { return value_; }
  explicit operator bool() const noexcept {
    return value_ && value_ != INVALID_HANDLE_VALUE;
  }
  HANDLE release() noexcept { return std::exchange(value_, nullptr); }
  void reset(HANDLE next = nullptr) noexcept {
    if (next == value_)
      return;
    DWORD error = GetLastError();
    if (*this)
      Traits::close(value_);
    value_ = next;
    SetLastError(error);
  }
};
using KernelHandle = UniqueHandle<KernelHandleTraits>;
using InternetHandle = UniqueHandle<InternetHandleTraits>;
struct PreserveLastError {
  DWORD value = GetLastError();
  ~PreserveLastError() { SetLastError(value); }
};
} // namespace wwe
