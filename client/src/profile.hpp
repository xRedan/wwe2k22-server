#pragma once
#include <cstdint>
namespace wwe::profile {
// WWE 2K22 PC 1.21: supported only with the executable digest fixed by
// build.py. RVAs retained from the existing Ghidra reconstruction; never
// scan/patch an unknown build. Runtime locations are image base + RVA, so ASLR
// is supported.
inline constexpr uintptr_t cdn_initializer = 0x19491d0;
inline constexpr uintptr_t session_reader = 0x1960fb0;
// Public discovery task: preserve native metadata requests, ping and UI builder.
inline constexpr uintptr_t query_start = 0x18d55a0;
inline constexpr uintptr_t query_results_reset = 0x18dedc0;
inline constexpr uintptr_t query_candidate_append = 0x18d6aa0;
inline constexpr uintptr_t query_filter_value = 0x18c1460;
inline constexpr uintptr_t platform_error = 0x18a1990;
inline constexpr uintptr_t matchmaking_selector = 0x34fdc50;
inline constexpr uintptr_t lobby_manager = 0x36e5210;
inline constexpr uintptr_t current_match = 0x34a3878;
// Last native SESSION_DATA copy; published only if bound to the current room.
inline constexpr uintptr_t session_descriptor = 0x34a38a8;
inline constexpr uintptr_t thread_cleanup = 0x2329060;
inline constexpr uintptr_t thread_system = 0x356afb0;
inline constexpr uintptr_t tls_index = 0x3529e98;
// Fields of the native lobby manager, observed rather than replaced.
inline constexpr uintptr_t lobby_active = 0x6090;
inline constexpr uintptr_t lobby_id = 0x6088;
inline constexpr uintptr_t own_steam_id = 0x5f80;
inline constexpr uintptr_t lobby_private = 0x5f60;
// CSteamID GetLobbyOwner uses a hidden result pointer on the supported ABI.
inline constexpr uintptr_t owner_slot = 0x118;
inline constexpr uintptr_t metadata_count_slot = 0xa8;
inline constexpr uintptr_t metadata_item_slot = 0xb0;
inline constexpr uintptr_t members_slot = 0x88;
inline constexpr uintptr_t member_limit_slot = 0x100;
inline constexpr uintptr_t set_type_slot = 0x108;
inline constexpr uintptr_t set_joinable_slot = 0x110;
} // namespace wwe::profile
