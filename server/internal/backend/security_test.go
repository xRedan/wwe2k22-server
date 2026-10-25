package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRefreshCapacityFailurePreservesUsableToken(t *testing.T) {
	s := testServer(t, false)
	tokens, err := s.issue("account")
	if err != nil {
		t.Fatal(err)
	}
	old := tokens["refreshToken"].(string)
	s.mu.Lock()
	for i := len(s.access); i < 4096; i++ {
		s.access[fmt.Sprint("filled-", i)] = time.Now().Add(time.Hour)
	}
	s.mu.Unlock()
	data := map[string]any{"accountType": "platform", "credentials": map[string]any{"type": "refresh", "refreshToken": old}}
	code, _, _ := request(t, s, "/core/ssoRefresh/v1/auth/tokens", data, nil)
	if code != 503 {
		t.Fatalf("want capacity refusal, got %d", code)
	}
	s.mu.Lock()
	_, exists := s.refresh[old]
	delete(s.access, "filled-100")
	s.mu.Unlock()
	if !exists {
		t.Fatal("a failed renewal consumed the only retry credential")
	}
	code, _, _ = request(t, s, "/core/ssoRefresh/v1/auth/tokens", data, nil)
	if code != 200 {
		t.Fatalf("retry failed: %d", code)
	}
	code, _, _ = request(t, s, "/core/ssoRefresh/v1/auth/tokens", data, nil)
	if code != 401 {
		t.Fatal("old token was not consumed after successful renewal")
	}
}
func TestPersistentCounterCapacityRejectsWholeBatch(t *testing.T) {
	existing := map[counterKey]int64{}
	for i := 0; i < 16384; i++ {
		existing[counterKey{"user", fmt.Sprint(i), "wins"}] = 7
	}
	data := map[string]any{"Leaderboards": []any{"0", "new"}, "RankKey": "wins", "Value": 1}
	if _, err := counterChanges(existing, "user", data, false); statusCode(err, 0) != 503 {
		t.Fatalf("unbounded new counters accepted: %v", err)
	}
	if existing[counterKey{"user", "0", "wins"}] != 7 {
		t.Fatal("partial counter update")
	}
	data["Leaderboards"] = []any{"0"}
	if _, err := counterChanges(existing, "user", data, false); err != nil {
		t.Fatal("existing records must remain updateable:", err)
	}
}
func TestOversizedProfileIsRejectedBeforeMutation(t *testing.T) {
	s := testServer(t, false)
	sid, uid := loginREST(t, s, "security-test-user")
	ids := make([]any, 1024)
	for i := range ids {
		ids[i] = strings.Repeat("x", 256)
	}
	code, _, _ := request(t, s, "/api/PlayerSet", map[string]any{"BlockedSIDs": ids}, map[string]string{"X-Sessionid": sid})
	if code != 413 {
		t.Fatalf("oversized persistent profile accepted: %d", code)
	}
	s.mu.Lock()
	_, changed := s.profiles[uid]["BlockedSIDs"]
	s.mu.Unlock()
	if changed {
		t.Fatal("oversized profile was committed")
	}
}
func TestAccessKeyReaderRejectsNonRegularOrOversizedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", 64)+strings.Repeat(" ", 1024)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAccessKey(p); err == nil {
		t.Fatal("unbounded padded access-key file accepted")
	}
	if _, err := readAccessKey(dir); err == nil {
		t.Fatal("directory accepted as key")
	}
}
func TestPersistentRecordLimitsPreserveExistingIdentities(t *testing.T) {
	s := testServer(t, false)
	_, uid := loginREST(t, s, "existing-user")
	s.mu.Lock()
	for i := len(s.profiles); i < maxProfiles; i++ {
		s.profiles[fmt.Sprint("profile-", i)] = map[string]any{}
	}
	for i := 0; i < maxNoticeUsers; i++ {
		s.notices[fmt.Sprint("notice-", i)] = map[string]int64{"Eula": 2}
	}
	existingNoticeID := identity(map[string]any{"Login": "existing-notice"})
	delete(s.notices, "notice-0")
	s.notices[existingNoticeID] = map[string]int64{"Eula": 2}
	s.mu.Unlock()
	code, _, _ := request(t, s, "/api/Login", map[string]any{"Login": "new-user"}, nil)
	if code != 503 {
		t.Fatalf("new profile over capacity: %d", code)
	}
	code, _, _ = request(t, s, "/api/Login", map[string]any{"Login": "existing-user"}, nil)
	if code != 200 {
		t.Fatal("existing identity blocked by profile capacity")
	}
	code, _, _ = request(t, s, "/api/EulaAccept", map[string]any{"Login": "new-notice", "Version": 2}, nil)
	if code != 503 {
		t.Fatalf("new notice identity over capacity: %d", code)
	}
	code, _, _ = request(t, s, "/api/EulaAccept", map[string]any{"Login": "existing-notice", "Version": 2}, nil)
	if code != 200 {
		t.Fatalf("existing notice refused: %d", code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.profiles) != maxProfiles || len(s.notices) != maxNoticeUsers || s.profiles[uid] == nil {
		t.Fatal("capacity rejection changed existing state")
	}
}
func TestConcurrentRefreshHasExactlyOneWinner(t *testing.T) {
	s := testServer(t, false)
	tokens, err := s.issue("owner")
	if err != nil {
		t.Fatal(err)
	}
	old := tokens["refreshToken"].(string)
	result := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := s.issueTokens("", &old); result <- err }()
	}
	successes, denied := 0, 0
	for i := 0; i < 2; i++ {
		err := <-result
		if err == nil {
			successes++
		} else if statusCode(err, 0) == 401 {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || denied != 1 {
		t.Fatal("same refresh token issued multiple credentials")
	}
}
