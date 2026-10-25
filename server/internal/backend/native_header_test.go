package backend

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Inspect bytes on the TCP stream: http.Header.Get normalizes field names and
// cannot detect changes to the native peer's established header spelling.
func TestNativeFieldListHeaderWireSpelling(t *testing.T) {
	s := testServer(t, false)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(s.Origin(), "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(conn, "POST /Session/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16\r\nConnection: close\r\n\r\n%s", string(make([]byte, 16))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	var head strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("\r\nVCFIELDLIST_SIZE: %d\r\n", len(body))
	if !strings.Contains(head.String(), expected) {
		t.Fatalf("native header spelling changed on the wire; want %q, got:\n%s", expected, head.String())
	}
	if strings.Contains(head.String(), "Vcfieldlist_size:") {
		t.Fatal("canonicalized duplicate native header")
	}
}
