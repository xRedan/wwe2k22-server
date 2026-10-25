package backend

// Persistent records survive session expiry, so session limits alone do not
// bound their memory or disk growth. Existing records remain readable/updateable.
const (
	maxProfiles       = 4096
	maxNoticeUsers    = 4096
	maxCounterEntries = 16384
	maxProfileBytes   = 32 * 1024
)
