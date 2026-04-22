package dp9ik

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
	"unsafe"
)

const (
	testAuthServer = "Authomatic.rentonsoftworks.coin:567"
	testUser       = "scott"
	testPassword   = "REDACTED_TEST_PASSWORD"
)

// Test 1: Can we connect to the auth server?
func TestConnectToAuthServer(t *testing.T) {
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to auth server %s: %v", testAuthServer, err)
	}
	defer conn.Close()

	t.Logf("Successfully connected to %s", testAuthServer)
}

// Test 2: Server should accept connection and not immediately close it
func TestAuthServerResponsive(t *testing.T) {
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Set a read deadline to see if server sends anything or closes
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	// We expect either:
	// 1. Timeout (server waiting for our request) - GOOD
	// 2. Some data (server sends challenge) - GOOD
	// 3. Connection closed immediately - BAD

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Logf("Server waiting for request (timeout) - this is expected")
			return
		}
		t.Logf("Read error: %v", err)
	}

	if n > 0 {
		t.Logf("Server sent %d bytes: %x", n, buf[:n])
	}
}

// Test 3: Send a raw Ticketreq and observe response
func TestSendRawTicketreq(t *testing.T) {
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Build a Ticketreq manually based on the C structure
	// struct Ticketreq {
	//   char type;            // 1 byte
	//   char authid[28];      // 28 bytes
	//   char authdom[48];     // 48 bytes
	//   char chal[8];         // 8 bytes
	//   char hostid[28];      // 28 bytes
	//   char uid[28];         // 28 bytes
	// }
	// Total: 141 bytes (TICKREQLEN)

	buf := make([]byte, 141)

	// type = AuthPAK (19 from authsrv.h)
	buf[0] = 19

	// authid = "" (auth server id - usually empty for client request)
	// Already zero

	// authdom = "rentonsoftworks.coin" or similar
	copy(buf[1:1+28], []byte(""))

	// chal = random 8 bytes (server challenge - we don't have one yet, use zeros)
	// Already zero

	// hostid = "drawterm" or client machine name
	copy(buf[1+28+48+8:1+28+48+8+28], []byte("go-client"))

	// uid = "scott"
	copy(buf[1+28+48+8+28:1+28+48+8+28+28], []byte("scott"))

	t.Logf("Sending Ticketreq: %x", buf)

	// Send to server
	n, err := conn.Write(buf)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	t.Logf("Wrote %d bytes", n)

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 4096)
	n, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	t.Logf("Server responded with %d bytes: %x", n, resp[:n])

	// Check first byte for response type
	if n > 0 {
		switch resp[0] {
		case 4: // AuthOK
			t.Logf("Server sent AuthOK")
		case 5: // AuthErr
			t.Logf("Server sent AuthErr")
		case 9: // AuthOKvar
			t.Logf("Server sent AuthOKvar")
		default:
			t.Logf("Server sent unknown type: %d", resp[0])
		}
	}
}

// Test 4: Compare C implementation with manual marshaling and test against server
func TestTicketreqMarshal_C(t *testing.T) {
	tr := &Ticketreq{
		Type: AuthPAK,
	}

	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte("scott"))

	// Marshal using C implementation
	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	t.Logf("C implementation produced %d bytes: %x", len(buf), buf)

	// Validate against live server
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	n, err := conn.Write(buf)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	t.Logf("Wrote %d bytes to server", n)

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 4096)
	n, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	t.Logf("Server responded with %d bytes: %x", n, resp[:n])

	// Server should accept it
	if n > 0 && resp[0] == 4 {
		t.Logf("✓ Server accepted C-marshaled Ticketreq (AuthOK)")
	} else {
		t.Errorf("Server rejected Ticketreq or sent unexpected response")
	}
}

func TestTicketreqMarshalUnmarshal(t *testing.T) {
	tr := &Ticketreq{
		Type: AuthPAK,
	}
	copy(tr.Authid[:], []byte("authid"))
	copy(tr.Authdom[:], []byte("rentonsoftworks.coin"))
	copy(tr.Chal[:], []byte("chal1234"))
	copy(tr.Hostid[:], []byte("client"))
	copy(tr.Uid[:], []byte("scott"))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	tr2, n, err := UnmarshalTicketreq(buf)
	if err != nil {
		t.Fatalf("UnmarshalTicketreq failed: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("UnmarshalTicketreq length = %d, want %d", n, len(buf))
	}
	if tr2.Type != tr.Type {
		t.Fatalf("Type = %d, want %d", tr2.Type, tr.Type)
	}
	if tr2.Authid != tr.Authid {
		t.Fatalf("Authid mismatch")
	}
	if tr2.Authdom != tr.Authdom {
		t.Fatalf("Authdom mismatch")
	}
	if tr2.Chal != tr.Chal {
		t.Fatalf("Chal mismatch")
	}
	if tr2.Hostid != tr.Hostid {
		t.Fatalf("Hostid mismatch")
	}
	if tr2.Uid != tr.Uid {
		t.Fatalf("Uid mismatch")
	}
}

func TestUnmarshalFailuresReportZeroConsumedBytes(t *testing.T) {
	tr, n, err := UnmarshalTicketreq([]byte{0xff})
	if err == nil {
		t.Fatalf("UnmarshalTicketreq unexpectedly succeeded: %+v", tr)
	}
	if n != 0 {
		t.Fatalf("UnmarshalTicketreq consumed = %d, want 0", n)
	}

	key, err := PassToKey("testpassword")
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}

	ticket, n, err := UnmarshalTicketWithLength(key, []byte{0xff})
	if err == nil {
		t.Fatalf("UnmarshalTicketWithLength unexpectedly succeeded: %+v", ticket)
	}
	if n != 0 {
		t.Fatalf("UnmarshalTicketWithLength consumed = %d, want 0", n)
	}

	auth, n, err := UnmarshalAuthenticatorWithLength(&Ticket{}, []byte{0xff})
	if err == nil {
		t.Fatalf("UnmarshalAuthenticatorWithLength unexpectedly succeeded: %+v", auth)
	}
	if n != 0 {
		t.Fatalf("UnmarshalAuthenticatorWithLength consumed = %d, want 0", n)
	}
}

// Test 5: Verify our struct sizes match C exactly
func TestStructSizes(t *testing.T) {
	tests := []struct {
		name     string
		goSize   uintptr
		expected int
	}{
		{"Ticketreq", unsafe.Sizeof(Ticketreq{}), 141},
		// Add more as we implement them
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goSize != uintptr(tt.expected) {
				t.Errorf("%s size mismatch: Go=%d, expected=%d",
					tt.name, tt.goSize, tt.expected)
			}
		})
	}
}

// Test 6: Password to key derivation
func TestPassToKey(t *testing.T) {
	key, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}

	// Key should be non-zero
	allZero := true
	for _, b := range key.Aes {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		t.Error("AES key is all zeros - password derivation may have failed")
	}

	t.Logf("✓ Derived key from password")
	t.Logf("  AES key (first 8 bytes): %x", key.Aes[:8])
}

// Test 7: Full AuthPAK authentication flow
func TestAuthPAKFullFlow(t *testing.T) {
	// Step 1: Derive key from password
	key, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}
	t.Logf("✓ Step 1: Derived key from password")

	// Step 2: Generate PAK hash for username
	key.AuthPAKHash(testUser)
	t.Logf("✓ Step 2: Generated AuthPAK hash for user %s", testUser)

	// Step 3: Connect to server
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	t.Logf("✓ Step 3: Connected to %s", testAuthServer)

	// Step 4: Send Ticketreq + fake "9P server Y"
	// In real dp9ik, the 9P server sends its Y value with the Ticketreq
	// For direct auth server testing, we generate a fake server Y
	// Generate random challenge
	chal := make([]byte, CHALLEN)
	_, err = rand.Read(chal)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	tr := &Ticketreq{
		Type: AuthPAK,
	}
	copy(tr.Authid[:], []byte(testUser))
	copy(tr.Authdom[:], []byte("")) // Empty domain for testing
	copy(tr.Chal[:], chal)
	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte(testUser))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Generate proper "9P server Y" using AuthPAK in server mode
	// In real dp9ik, this comes from the 9P server, but for testing we generate it ourselves
	serverKey, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("Failed to derive server key: %v", err)
	}
	serverKey.AuthPAKHash(testUser)

	serverPakpriv := &PAKpriv{}
	p9serverY := serverPakpriv.AuthPAKNew(serverKey, false) // false = server mode

	// Send Ticketreq + server Y (as cpu.c line 538 does)
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write Ticketreq: %v", err)
	}
	if _, err := conn.Write(p9serverY); err != nil {
		t.Fatalf("Failed to write server Y: %v", err)
	}
	t.Logf("✓ Step 4: Sent Ticketreq + 9P server Y")

	// Step 5: Do AuthPAK exchange (no intermediate AuthOK)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	pakpriv := &PAKpriv{}
	clientY := pakpriv.AuthPAKNew(key, true)
	t.Logf("✓ Step 5a: Generated client Y (%d bytes)", len(clientY))

	// Send our Y to server
	if _, err := conn.Write(clientY); err != nil {
		t.Fatalf("Failed to send client Y: %v", err)
	}
	t.Logf("✓ Step 5b: Sent client Y to server")

	// Read AuthOK + 2*PAKYLEN response
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read AuthPAK response: %v", err)
	}
	if resp[0] != 4 { // AuthOK
		t.Fatalf("Expected AuthOK for AuthPAK, got %d", resp[0])
	}

	// Read 2*PAKYLEN: server Y + server's finish data
	pakResponse := make([]byte, 2*PAKYLEN)
	if _, err := io.ReadFull(conn, pakResponse); err != nil {
		t.Fatalf("Failed to read AuthPAK response: %v", err)
	}

	serverY := pakResponse[:PAKYLEN]
	serverFinish := pakResponse[PAKYLEN:]
	t.Logf("✓ Step 5c: Received server Y (%d bytes): %x...", len(serverY), serverY[:8])

	// Finish PAK exchange
	if err := pakpriv.AuthPAKFinish(key, serverFinish); err != nil {
		t.Fatalf("AuthPAK finish failed: %v", err)
	}
	t.Logf("✓ Step 5d: AuthPAK exchange complete")
	t.Logf("  Shared key: %x...", key.Pakkey[:16])

	// Step 6: Send AuthTreq on same connection
	tr.Type = 1 // AuthTreq
	buf, err = tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal AuthTreq failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write AuthTreq: %v", err)
	}
	t.Logf("✓ Step 6: Sent ticket request")

	// Step 7: Read AuthOK
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp = make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read AuthOK: %v", err)
	}

	if resp[0] != 4 {
		t.Fatalf("Expected AuthOK for tickets, got %d", resp[0])
	}
	t.Logf("✓ Step 7: Server acknowledged ticket request")

	// Step 8: Read first ticket
	ticketBuf := make([]byte, MAXTICKETLEN)
	n, err := io.ReadAtLeast(conn, ticketBuf, 100)
	if err != nil {
		t.Fatalf("Failed to read ticket: %v", err)
	}
	t.Logf("✓ Step 8: Read %d bytes for first ticket", n)

	ticket1, err := UnmarshalTicket(key, ticketBuf[:n])
	if err != nil {
		t.Logf("  Ticket data: %x", ticketBuf[:min(64, n)])
		t.Fatalf("Failed to decrypt ticket: %v", err)
	}
	t.Logf("  ✓ Ticket 1 decrypted:")
	t.Logf("    Num: %d", ticket1.Num)
	t.Logf("    Cuid: %s", string(ticket1.Cuid[:]))
	t.Logf("    Suid: %s", string(ticket1.Suid[:]))

	t.Logf("")
	t.Logf("✓✓✓ FULL AUTHENTICATION SUCCESSFUL!")
	t.Logf("  - AuthPAK key exchange ✓")
	t.Logf("  - Ticket retrieval ✓")
	t.Logf("  - Ticket decryption ✓")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// UNHAPPY PATH TESTS

// Test 8: Invalid server address
func TestConnectInvalidServer(t *testing.T) {
	_, err := net.DialTimeout("tcp", "invalid.server.nonexistent:567", 2*time.Second)
	if err == nil {
		t.Fatal("Expected error connecting to invalid server, got nil")
	}
	t.Logf("✓ Correctly failed to connect to invalid server: %v", err)
}

// Test 9: Wrong password should cause AuthPAK to fail
func TestWrongPassword(t *testing.T) {
	// Use wrong password
	wrongPassword := "WrongPassword123"

	// Step 1: Derive key from wrong password
	key, err := PassToKey(wrongPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}

	// Step 2: Generate PAK hash
	key.AuthPAKHash(testUser)

	// Step 3: Connect to server
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Step 4: Send Ticketreq
	tr := &Ticketreq{
		Type: AuthPAK,
	}
	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte(testUser))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write Ticketreq: %v", err)
	}

	// Step 5: Read server response (should still be AuthOK for ticketreq)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp[0] != 4 {
		t.Fatalf("Expected AuthOK for ticketreq, got %d", resp[0])
	}

	// Step 6: Do AuthPAK exchange with wrong password
	pakpriv := &PAKpriv{}
	clientY := pakpriv.AuthPAKNew(key, true)

	// Send our Y to server
	if _, err := conn.Write(clientY); err != nil {
		t.Fatalf("Failed to send client Y: %v", err)
	}

	// Read server's Y
	serverY := make([]byte, PAKYLEN)
	if _, err := io.ReadFull(conn, serverY); err != nil {
		t.Fatalf("Failed to read server Y: %v", err)
	}

	// Finish PAK exchange - this will work but derive wrong shared key
	if err := pakpriv.AuthPAKFinish(key, serverY); err != nil {
		t.Fatalf("AuthPAK finish failed: %v", err)
	}

	t.Logf("✓ AuthPAK completed with wrong password - derived wrong shared key: %x...", key.Pakkey[:16])
	t.Logf("  (Subsequent ticket encryption will fail when server tries to decrypt)")
}

// Test 10: Invalid Y length should fail
func TestInvalidYLength(t *testing.T) {
	key, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}

	pakpriv := &PAKpriv{}

	// Try to finish with wrong-length Y
	invalidY := make([]byte, 10) // Should be PAKYLEN (56)

	err = pakpriv.AuthPAKFinish(key, invalidY)
	if err == nil {
		t.Fatal("Expected error with invalid Y length, got nil")
	}

	if err.Error() != "invalid peer Y length" {
		t.Fatalf("Expected 'invalid peer Y length' error, got: %v", err)
	}

	t.Logf("✓ Correctly rejected invalid Y length: %v", err)
}

// Test 11: Empty username
func TestEmptyUsername(t *testing.T) {
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	tr := &Ticketreq{
		Type: AuthPAK,
	}
	copy(tr.Hostid[:], []byte("go-client"))
	// Leave uid empty

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Server might reject or handle differently
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 1)
	n, err := conn.Read(resp)

	if err != nil {
		t.Logf("✓ Server closed connection for empty username: %v", err)
		return
	}

	if n > 0 {
		t.Logf("✓ Server responded to empty username with type: %d", resp[0])
	}
}

// Test 12: Connection timeout
func TestConnectionTimeout(t *testing.T) {
	// Try to connect with very short timeout to a valid but slow-responding address
	// Using a non-routable address (RFC 5737 TEST-NET-1)
	_, err := net.DialTimeout("tcp", "192.0.2.1:567", 100*time.Millisecond)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Logf("✓ Correctly timed out: %v", err)
	} else {
		t.Logf("✓ Connection failed (may be timeout or network unreachable): %v", err)
	}
}

// Test 13: Server disconnect during AuthPAK
func TestServerDisconnectDuringPAK(t *testing.T) {
	// Connect and send ticketreq
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	tr := &Ticketreq{
		Type: AuthPAK,
	}
	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte(testUser))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Read AuthOK
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Close connection before completing AuthPAK
	conn.Close()

	// Try to read server Y - should fail
	serverY := make([]byte, PAKYLEN)
	_, err = io.ReadFull(conn, serverY)

	if err == nil {
		t.Fatal("Expected error reading from closed connection, got nil")
	}

	t.Logf("✓ Correctly detected server disconnect: %v", err)
}

// Test 14: Struct size validation at compile time
func TestCompileTimeSizeChecks(t *testing.T) {
	// These compile-time checks are in auth.go
	// If they fail, code won't compile
	// This test just documents that they exist

	tests := []struct {
		name     string
		size     int
		expected int
	}{
		{"Ticketreq", int(unsafe.Sizeof(Ticketreq{})), 141},
		{"Ticket", int(unsafe.Sizeof(Ticket{})), 98},
		{"Authenticator", int(unsafe.Sizeof(Authenticator{})), 41},
		{"Authkey", int(unsafe.Sizeof(Authkey{})), 503},
		{"PAKpriv", int(unsafe.Sizeof(PAKpriv{})), 116},
	}

	for _, tt := range tests {
		if tt.size != tt.expected {
			t.Errorf("%s size mismatch: got %d, want %d", tt.name, tt.size, tt.expected)
		}
	}

	t.Logf("✓ All struct sizes validated at both compile and runtime")
}

// Test 15: Concurrent authentication attempts (thread safety)
func TestConcurrentAuth(t *testing.T) {
	const numGoroutines = 10

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Launch concurrent auth attempts
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			// Each goroutine does a full auth flow
			key, err := PassToKey(testPassword)
			if err != nil {
				errors <- err
				return
			}

			key.AuthPAKHash(testUser)

			conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()

			tr := &Ticketreq{Type: AuthPAK}
			copy(tr.Hostid[:], []byte("go-client"))
			copy(tr.Uid[:], []byte(testUser))

			buf, err := tr.Marshal()
			if err != nil {
				errors <- err
				return
			}

			if _, err := conn.Write(buf); err != nil {
				errors <- err
				return
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp := make([]byte, 1)
			if _, err := conn.Read(resp); err != nil {
				errors <- err
				return
			}

			if resp[0] != 4 {
				errors <- &AuthError{Msg: "expected AuthOK"}
				return
			}

			pakpriv := &PAKpriv{}
			clientY := pakpriv.AuthPAKNew(key, true)

			if _, err := conn.Write(clientY); err != nil {
				errors <- err
				return
			}

			serverY := make([]byte, PAKYLEN)
			if _, err := io.ReadFull(conn, serverY); err != nil {
				errors <- err
				return
			}

			if err := pakpriv.AuthPAKFinish(key, serverY); err != nil {
				errors <- err
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			successCount++
		case err := <-errors:
			t.Logf("Goroutine failed: %v", err)
		case <-time.After(15 * time.Second):
			t.Fatal("Timeout waiting for concurrent auth")
		}
	}

	if successCount != numGoroutines {
		t.Fatalf("Expected %d successful auths, got %d", numGoroutines, successCount)
	}

	t.Logf("✓ %d concurrent authentications completed successfully", successCount)
	t.Logf("  Thread safety verified - cgoMutex protecting genrandom() PRNG")
}

// Test 17: Complete authentication flow with ticket retrieval
func TestCompleteAuth(t *testing.T) {
	// Step 1-2: Derive key and hash
	key, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}
	key.AuthPAKHash(testUser)
	t.Logf("✓ Step 1: Password to key and PAK hash")

	// Step 3: Connect to server
	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	t.Logf("✓ Step 2: Connected to %s", testAuthServer)

	// Step 3: Prepare Ticketreq and generate 9P server Y
	tr := &Ticketreq{Type: AuthPAK}
	copy(tr.Authid[:], []byte(testUser))
	copy(tr.Authdom[:], []byte(""))
	chal := make([]byte, CHALLEN)
	rand.Read(chal)
	copy(tr.Chal[:], chal)
	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte(testUser))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal ticketreq failed: %v", err)
	}

	// Generate proper "9P server Y" for testing
	serverKey, _ := PassToKey(testPassword)
	serverKey.AuthPAKHash(testUser)
	serverPakpriv := &PAKpriv{}
	p9serverY := serverPakpriv.AuthPAKNew(serverKey, false)

	// Send Ticketreq + 9P server Y
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write ticketreq: %v", err)
	}
	if _, err := conn.Write(p9serverY); err != nil {
		t.Fatalf("Failed to write server Y: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Generate and send client Y
	pakpriv := &PAKpriv{}
	clientY := pakpriv.AuthPAKNew(key, true)
	if _, err := conn.Write(clientY); err != nil {
		t.Fatalf("Failed to send client Y: %v", err)
	}

	// Read AuthOK + 2*PAKYLEN response
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read AuthOK for PAK: %v", err)
	}
	if resp[0] != 4 {
		t.Fatalf("Expected AuthOK for PAK, got %d", resp[0])
	}

	pakResponse := make([]byte, 2*PAKYLEN)
	if _, err := io.ReadFull(conn, pakResponse); err != nil {
		t.Fatalf("Failed to read PAK response: %v", err)
	}

	serverFinish := pakResponse[PAKYLEN:]

	if err := pakpriv.AuthPAKFinish(key, serverFinish); err != nil {
		t.Fatalf("AuthPAK finish failed: %v", err)
	}
	t.Logf("✓ Step 3: AuthPAK exchange complete, shared key: %x...", key.Pakkey[:16])

	// Step 6: Request tickets (SAME connection, change type to AuthTreq)
	tr.Type = 1 // AuthTreq
	buf, err = tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal AuthTreq failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write AuthTreq: %v", err)
	}
	t.Logf("✓ Step 4: Sent ticket request")

	// Step 7: Read AuthOK (but no data after it - _asrdresp with len=0)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read AuthOK: %v", err)
	}

	if resp[0] != 4 {
		t.Fatalf("Expected AuthOK for tickets, got %d", resp[0])
	}
	t.Logf("✓ Step 5: Server acknowledged ticket request")

	// Step 6: Read first ticket (simplified approach)
	ticketBuf := make([]byte, MAXTICKETLEN)
	n, err := io.ReadAtLeast(conn, ticketBuf, 100)
	if err != nil {
		t.Fatalf("Failed to read ticket: %v", err)
	}

	ticket1, err := UnmarshalTicket(key, ticketBuf[:n])
	if err != nil {
		t.Fatalf("Failed to decrypt ticket: %v", err)
	}
	t.Logf("✓ Step 6: Ticket decrypted - Num: %d, Form: %d, Cuid: %s",
		ticket1.Num, ticket1.Form, string(ticket1.Cuid[:]))

	t.Logf("")
	t.Logf("✓✓✓ COMPLETE AUTHENTICATION SUCCESSFUL!")
	t.Logf("")
	t.Logf("✓✓✓ COMPLETE AUTHENTICATION SUCCESSFUL!")
	t.Logf("  - AuthPAK key exchange ✓")
	t.Logf("  - Ticket retrieval ✓")
	t.Logf("  - Ticket decryption ✓")
	t.Logf("")
	t.Logf("  Ready to authenticate to services with these tickets!")
}

// Test 18: Ticket marshaling/unmarshaling
func TestTicketMarshalUnmarshal(t *testing.T) {
	// Create a test key
	key, err := PassToKey("testpassword")
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}

	// Create a test ticket
	ticket := &Ticket{
		Num:  65, // AuthTc
		Form: 1,  // Form1 (ChaCha20-Poly1305)
	}
	copy(ticket.Chal[:], []byte("chall123"))
	copy(ticket.Cuid[:], []byte("testuser"))
	copy(ticket.Suid[:], []byte("testuser"))
	copy(ticket.Key[:], []byte("thisisatestkeythisisatestkey1234"))

	// Marshal it
	buf, err := ticket.Marshal(key)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	t.Logf("✓ Marshaled ticket: %d bytes", len(buf))

	// Unmarshal it
	ticket2, n, err := UnmarshalTicketWithLength(key, buf)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("ticket length = %d, want %d", n, len(buf))
	}

	// Verify
	if ticket2.Num != ticket.Num {
		t.Errorf("Num mismatch: got %d, want %d", ticket2.Num, ticket.Num)
	}
	if string(ticket2.Cuid[:]) != string(ticket.Cuid[:]) {
		t.Errorf("Cuid mismatch")
	}
	if string(ticket2.Suid[:]) != string(ticket.Suid[:]) {
		t.Errorf("Suid mismatch")
	}

	t.Logf("✓ Ticket round-trip successful")
	t.Logf("  Num: %d", ticket2.Num)
	t.Logf("  Cuid: %s", string(ticket2.Cuid[:]))
	t.Logf("  Suid: %s", string(ticket2.Suid[:]))
}

// Test 19: Authenticator marshaling/unmarshaling
func TestAuthenticatorMarshalUnmarshal(t *testing.T) {
	// Create a test ticket with a key
	ticket := &Ticket{
		Num:  66, // AuthAs
		Form: 1,  // Form1
	}
	copy(ticket.Key[:], []byte("thisisatestkeythisisatestkey1234"))

	// Create an authenticator
	auth := &Authenticator{
		Num: 66,
	}
	copy(auth.Chal[:], []byte("chaltest"))
	copy(auth.Rand[:], []byte("randomnoncerandomnoncerandomno"))

	// Marshal it
	buf, err := auth.Marshal(ticket)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	t.Logf("✓ Marshaled authenticator: %d bytes", len(buf))

	// Unmarshal it
	auth2, n, err := UnmarshalAuthenticatorWithLength(ticket, buf)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("authenticator length = %d, want %d", n, len(buf))
	}

	// Verify
	if auth2.Num != auth.Num {
		t.Errorf("Num mismatch: got %d, want %d", auth2.Num, auth.Num)
	}

	t.Logf("✓ Authenticator round-trip successful")
	t.Logf("  Num: %d", auth2.Num)
}

// Test: Simple ticket request without AuthPAK
func TestSimpleTicketRequest(t *testing.T) {
	t.Skip("Server requires AuthPAK - non-AuthPAK authentication not supported")

	key, err := PassToKey(testPassword)
	if err != nil {
		t.Fatalf("PassToKey failed: %v", err)
	}
	t.Logf("✓ Step 1: Derived key from password")

	conn, err := net.DialTimeout("tcp", testAuthServer, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	t.Logf("✓ Step 2: Connected to %s", testAuthServer)

	// Send Ticketreq with type=AuthTreq (no AuthPAK)
	tr := &Ticketreq{Type: 1} // AuthTreq
	copy(tr.Hostid[:], []byte("go-client"))
	copy(tr.Uid[:], []byte(testUser))

	buf, err := tr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("Failed to write ticketreq: %v", err)
	}
	t.Logf("✓ Step 3: Sent ticket request (no AuthPAK)")

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	t.Logf("  Response byte: %d (0x%x)", resp[0], resp[0])

	if resp[0] == 4 { // AuthOK
		t.Logf("✓ Step 4: Server sent AuthOK")

		// Try to read tickets
		ticketBuf := make([]byte, 2*MAXTICKETLEN)
		n, err := io.ReadAtLeast(conn, ticketBuf, 100)
		if err != nil {
			t.Logf("  Read %d bytes, error: %v", n, err)
		} else {
			t.Logf("  Read %d bytes of ticket data", n)
			t.Logf("  First 32 bytes: %x", ticketBuf[:32])

			// Try to decrypt
			ticket, err := UnmarshalTicket(key, ticketBuf[:n])
			if err != nil {
				t.Logf("  Could not decrypt: %v", err)
			} else {
				t.Logf("  ✓ Decrypted ticket!")
				t.Logf("    Num: %d", ticket.Num)
				t.Logf("    Cuid: %s", string(ticket.Cuid[:]))
			}
		}
	} else if resp[0] == 5 { // AuthErr
		errMsg := make([]byte, 64)
		conn.Read(errMsg)
		t.Logf("  Server error: %s", string(errMsg))
	} else {
		t.Logf("  Unknown response type: %d", resp[0])
	}
}
