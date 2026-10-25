package backend

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"
)

//go:embed documents.json
var documentsJSON []byte

func jsonNumber(s string) json.Number { return json.Number(s) }
func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case json.Number:
		return x != "0" && x != "0.0"
	}
	return true
}
func player(id string, now time.Time) map[string]any {
	return map[string]any{"ID": id, "SID": "", "DisplayName": "Giocatore locale", "CreatorRank": 0, "CreatedAt": now.UnixMicro() + 2208988800000000, "Language": "it", "Platforms": 0, "FirstParties": 0, "SSOEnable": false, "SSOID": "", "SSODisplayName": "", "ContentListUpload": []any{}, "ContentListDownload": []any{}}
}
func profileChanges(data map[string]any) (map[string]any, error) {
	stringsSet := map[string]int{"Language": 32, "DisplayName": 256, "SSOID": 256, "SSODisplayName": 256}
	allowed := []string{"CreatorRank", "SSOEnable", "BlockedSIDs", "ContentListUploadSub", "ContentListDownloadSub", "Platform", "FirstParty", "FirstPartyEnv", "GameID", "PatchVersion"}
	out := map[string]any{}
	for k, limit := range stringsSet {
		allowed = append(allowed, k)
		if v, has := data[k]; has {
			s, ok := jstr(v)
			if !ok || !validText(s, limit) {
				return nil, fail(400, "Invalid local profile string")
			}
			out[k] = s
		}
	}
	if v, has := data["CreatorRank"]; has {
		n, ok := jint(v)
		if !ok || n < 0 || n > math.MaxInt32 {
			return nil, fail(400, "Invalid local creator rank")
		}
		out["CreatorRank"] = n
	}
	if v, has := data["SSOEnable"]; has {
		b, ok := jbool(v)
		if !ok {
			return nil, fail(400, "Invalid local SSO flag")
		}
		out["SSOEnable"] = b
	}
	for _, key := range []string{"ContentListUploadSub", "ContentListDownloadSub"} {
		if v, has := data[key]; has {
			a, ok := v.([]any)
			if !ok {
				return nil, fail(400, "Invalid content patch list")
			}
			if len(a) > 0 {
				return nil, fail(501, "Content slot updates are not reconstructed")
			}
		}
	}
	if v, has := data["BlockedSIDs"]; has {
		a, ok := v.([]any)
		if !ok || len(a) > 1024 {
			return nil, fail(400, "Invalid local blocked-ID list")
		}
		for _, item := range a {
			s, ok := jstr(item)
			if !ok || len([]rune(s)) > 256 || strings.ContainsRune(s, 0) {
				return nil, fail(400, "Invalid local blocked-ID list")
			}
		}
		out["BlockedSIDs"] = a
	}
	if !fieldsAllowed(data, allowed...) {
		return nil, fail(501, "Unknown profile update fields")
	}
	return out, nil
}
func counterChanges(existing map[counterKey]int64, user string, data map[string]any, maximum bool) (map[counterKey]int64, error) {
	if !fieldsAllowed(data, "Leaderboards", "RankKey", "Value", "Platform", "FirstParty", "FirstPartyEnv", "GameID", "PatchVersion") {
		return nil, fail(501, "Unknown leaderboard increment fields")
	}
	names, ok := data["Leaderboards"].([]any)
	rank, valid := jstr(data["RankKey"])
	value, validN := jint(data["Value"])
	validName := func(s string) bool { return len(s) > 0 && validText(s, 1024) }
	if !ok || len(names) < 1 || len(names) > 100 {
		return nil, fail(400, "Invalid local leaderboard list")
	}
	if !valid || !validName(rank) {
		return nil, fail(400, "Invalid local leaderboard key")
	}
	if !validN || value < math.MinInt32 || value > math.MaxInt32 {
		return nil, fail(400, "Invalid local leaderboard increment")
	}
	changes := map[counterKey]int64{}
	seen := map[string]bool{}
	for _, v := range names {
		name, ok := jstr(v)
		if !ok || !validName(name) || seen[name] {
			return nil, fail(400, "Invalid local leaderboard list")
		}
		seen[name] = true
		k := counterKey{user, name, rank}
		previous, has := existing[k]
		total := value
		if maximum {
			if has && previous > total {
				total = previous
			}
		} else {
			if (value > 0 && previous > math.MaxInt64-value) || (value < 0 && previous < math.MinInt64-value) {
				return nil, fail(400, "Local leaderboard counter overflow")
			}
			total = previous + value
		}
		changes[k] = total
	}
	added := 0
	for k := range changes {
		if _, has := existing[k]; !has {
			added++
		}
	}
	if added > 0 && len(existing)+added > maxCounterEntries {
		return nil, fail(503, "Local counter capacity reached")
	}
	return changes, nil
}
func blacklist(data map[string]any) (map[string]any, error) {
	allowed := append(append([]string{}, contentContext...), "ContentIDs")
	if !fieldsAllowed(data, allowed...) {
		return nil, fail(400, "Invalid native content restriction query")
	}
	a, ok := data["ContentIDs"].([]any)
	if !ok || len(a) > 64 {
		return nil, fail(400, "Invalid native content identifier list")
	}
	for _, v := range a {
		if _, e := uuidID(v, true); e != nil {
			return nil, e
		}
	}
	return map[string]any{"ContentIDs": []any{}}, nil
}
func localAccount(steamID string) string {
	sum := sha256.Sum256([]byte(steamID))
	return "local-" + hex.EncodeToString(sum[:12])
}
