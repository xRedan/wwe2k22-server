#pragma once
#include <cstdint>
#include <optional>
#include <unordered_map>
namespace wwe {
// Caller holds the HTTP mutex. Closing an ancestor does not close its children.
// A generation prevents delayed cleanup from deleting a reused handle value.
class HttpHandles {
  struct Entry {
    uint64_t generation;
    bool asset;
    bool injected = false;
  };
  std::unordered_map<void *, Entry> connections_, requests_;
  uint64_t next_ = 0;
  size_t connection_limit_, request_limit_;
  bool remember(std::unordered_map<void *, Entry> &entries, void *h, bool asset,
                size_t limit) {
    if ((entries.size() >= limit && !entries.count(h)) || next_ == UINT64_MAX)
      return false;
    entries.insert_or_assign(h, Entry{++next_, asset});
    return true;
  }

public:
  struct Ticket {
    uint64_t connection = 0, request = 0;
  };
  explicit HttpHandles(size_t connections = 4096, size_t requests = 8192)
      : connection_limit_(connections), request_limit_(requests) {}
  bool connection(void *h) const { return connections_.count(h) != 0; }
  std::optional<bool> request(void *h) const {
    auto i = requests_.find(h);
    if (i == requests_.end())
      return {};
    return i->second.asset;
  }
  bool remember_connection(void *h, bool local) {
    requests_.erase(h);
    if (!local) {
      connections_.erase(h);
      return true;
    }
    return remember(connections_, h, false, connection_limit_);
  }
  bool remember_request(void *h, bool local, bool asset) {
    connections_.erase(h);
    if (!local) {
      requests_.erase(h);
      return true;
    }
    return remember(requests_, h, asset, request_limit_);
  }
  bool injected(void *h) const {
    auto it = requests_.find(h);
    return it != requests_.end() && it->second.injected;
  }
  void injected(void *h, Ticket ticket, bool value) {
    auto it = requests_.find(h);
    if (it != requests_.end() && it->second.generation == ticket.request)
      it->second.injected = value;
  }
  Ticket ticket(void *h) const {
    Ticket result;
    auto c = connections_.find(h), r = requests_.find(h);
    if (c != connections_.end())
      result.connection = c->second.generation;
    if (r != requests_.end())
      result.request = r->second.generation;
    return result;
  }
  void erase(void *h, Ticket ticket) {
    auto c = connections_.find(h);
    if (c != connections_.end() && c->second.generation == ticket.connection)
      connections_.erase(c);
    auto r = requests_.find(h);
    if (r != requests_.end() && r->second.generation == ticket.request)
      requests_.erase(r);
  }
};
} // namespace wwe
