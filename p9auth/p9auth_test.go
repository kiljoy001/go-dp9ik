package p9auth

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dp9ik "github.com/kiljoy001/go-dp9ik"
)

const (
	testAuthServerAddr = "Authomatic.rentonsoftworks.coin:567"
	testAuthDomain     = "rentonsoftworks.coin"
	testAuthUser       = "scott"
	testAuthPassword   = "REDACTED_TEST_PASSWORD"
)

func requireTestAuthServer(t *testing.T) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", testAuthServerAddr, 2*time.Second)
	if err != nil {
		t.Skipf("auth server unavailable: %v", err)
	}
	_ = conn.Close()
}

func TestHandshake(t *testing.T) {
	requireTestAuthServer(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		user string
		err  error
	}
	serverResult := make(chan result, 1)

	go func() {
		user, err := Handshake(serverConn, Config{
			Domain:   testAuthDomain,
			User:     testAuthUser,
			Password: testAuthPassword,
		})
		serverResult <- result{user: user, err: err}
		_ = serverConn.Close()
	}()

	if err := runTestClientHandshake(clientConn, testAuthPassword); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	res := <-serverResult
	if res.err != nil {
		t.Fatalf("server handshake failed: %v", res.err)
	}
	if res.user != testAuthUser {
		t.Fatalf("authenticated user = %q, want %q", res.user, testAuthUser)
	}
}

func TestHandshakeSetsAndClearsDeadline(t *testing.T) {
	requireTestAuthServer(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	recordingConn := &deadlineRecordingConn{Conn: serverConn}

	type result struct {
		user string
		err  error
	}
	serverResult := make(chan result, 1)

	go func() {
		user, err := Handshake(recordingConn, Config{
			Domain:   testAuthDomain,
			User:     testAuthUser,
			Password: testAuthPassword,
		})
		serverResult <- result{user: user, err: err}
		_ = recordingConn.Close()
	}()

	if err := runTestClientHandshake(clientConn, testAuthPassword); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	res := <-serverResult
	if res.err != nil {
		t.Fatalf("server handshake failed: %v", res.err)
	}
	if res.user != testAuthUser {
		t.Fatalf("authenticated user = %q, want %q", res.user, testAuthUser)
	}

	deadlines := recordingConn.Deadlines()
	if len(deadlines) < 2 {
		t.Fatalf("expected handshake to set and clear deadline, got %d calls", len(deadlines))
	}
	if deadlines[0].IsZero() {
		t.Fatalf("expected first deadline to be non-zero")
	}
	if !deadlines[len(deadlines)-1].IsZero() {
		t.Fatalf("expected final deadline reset to zero, got %v", deadlines[len(deadlines)-1])
	}
}

func TestHandshakeRejectsWrongPassword(t *testing.T) {
	requireTestAuthServer(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	clientErr := make(chan error, 1)

	go func() {
		_, err := Handshake(serverConn, Config{
			Domain:   testAuthDomain,
			User:     testAuthUser,
			Password: testAuthPassword,
		})
		serverErr <- err
		_ = serverConn.Close()
	}()

	go func() {
		clientErr <- runTestClientHandshake(clientConn, "wrong-password")
		_ = clientConn.Close()
	}()

	if err := <-serverErr; err == nil {
		t.Fatalf("expected server handshake to fail with wrong password")
	}
	_ = <-clientErr
}

func runTestClientHandshake(s net.Conn, password string) error {
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	offer, err := readCString(s, maxP9AnyMessage)
	if err != nil {
		return fmt.Errorf("read p9any offer: %w", err)
	}
	wantOffer := fmt.Sprintf("dp9ik@%s", testAuthDomain)
	if offer != wantOffer {
		return fmt.Errorf("unexpected p9any offer %q", offer)
	}
	if err := writeCString(s, fmt.Sprintf("dp9ik %s", testAuthDomain)); err != nil {
		return fmt.Errorf("write p9any selection: %w", err)
	}

	cchal := make([]byte, dp9ik.CHALLEN)
	if _, err := rand.Read(cchal); err != nil {
		return fmt.Errorf("generate client challenge: %w", err)
	}
	if _, err := s.Write(cchal); err != nil {
		return fmt.Errorf("write client challenge: %w", err)
	}

	serverOffer, err := readFixed(s, dp9ik.TICKREQLEN+dp9ik.PAKYLEN)
	if err != nil {
		return fmt.Errorf("read server offer: %w", err)
	}

	tr, _, err := dp9ik.UnmarshalTicketreq(serverOffer[:dp9ik.TICKREQLEN])
	if err != nil {
		return fmt.Errorf("decode ticketreq: %w", err)
	}
	if tr.Type != dp9ik.AuthPAK {
		return fmt.Errorf("unexpected ticketreq type %d", tr.Type)
	}
	fileServerY := append([]byte(nil), serverOffer[dp9ik.TICKREQLEN:]...)

	conn, err := net.DialTimeout("tcp", testAuthServerAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect auth server: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	clientKey, err := dp9ik.PassToKey(password)
	if err != nil {
		return fmt.Errorf("derive client key: %w", err)
	}
	clientKey.AuthPAKHash(testAuthUser)

	asReq := *tr
	copy(asReq.Hostid[:], []byte(testAuthUser))
	copy(asReq.Uid[:], []byte(testAuthUser))

	reqBuf, err := asReq.Marshal()
	if err != nil {
		return fmt.Errorf("marshal authpak request: %w", err)
	}
	if _, err := conn.Write(reqBuf); err != nil {
		return fmt.Errorf("write authpak request: %w", err)
	}
	if _, err := conn.Write(fileServerY); err != nil {
		return fmt.Errorf("write file-server pak y: %w", err)
	}

	clientPak := &dp9ik.PAKpriv{}
	clientY := clientPak.AuthPAKNew(clientKey, true)
	if _, err := conn.Write(clientY); err != nil {
		return fmt.Errorf("write client pak y: %w", err)
	}

	respCode, err := readFixed(conn, 1)
	if err != nil {
		return fmt.Errorf("read authpak status: %w", err)
	}
	if respCode[0] != dp9ik.AuthOK {
		return fmt.Errorf("unexpected authpak status %d", respCode[0])
	}

	pakResp, err := readFixed(conn, 2*dp9ik.PAKYLEN)
	if err != nil {
		return fmt.Errorf("read authpak response: %w", err)
	}
	serverY := append([]byte(nil), pakResp[:dp9ik.PAKYLEN]...)
	if err := clientPak.AuthPAKFinish(clientKey, pakResp[dp9ik.PAKYLEN:]); err != nil {
		return fmt.Errorf("finish client authpak: %w", err)
	}

	asReq.Type = dp9ik.AuthTreq
	reqBuf, err = asReq.Marshal()
	if err != nil {
		return fmt.Errorf("marshal ticket request: %w", err)
	}
	if _, err := conn.Write(reqBuf); err != nil {
		return fmt.Errorf("write ticket request: %w", err)
	}

	respCode, err = readFixed(conn, 1)
	if err != nil {
		return fmt.Errorf("read ticket status: %w", err)
	}
	if respCode[0] != dp9ik.AuthOK {
		return fmt.Errorf("unexpected ticket status %d", respCode[0])
	}

	clientTicket, serverTicketRaw, err := readAuthServerTickets(conn, clientKey)
	if err != nil {
		return fmt.Errorf("read tickets: %w", err)
	}

	auth := &dp9ik.Authenticator{Num: dp9ik.AuthAc}
	copy(auth.Chal[:], tr.Chal[:])
	if _, err := rand.Read(auth.Rand[:]); err != nil {
		return fmt.Errorf("generate client nonce: %w", err)
	}
	authBuf, err := auth.Marshal(clientTicket)
	if err != nil {
		return fmt.Errorf("marshal client authenticator: %w", err)
	}

	if _, err := s.Write(serverY); err != nil {
		return fmt.Errorf("write server pak y: %w", err)
	}

	serverMsg := make([]byte, 0, len(serverTicketRaw)+len(authBuf))
	serverMsg = append(serverMsg, serverTicketRaw...)
	serverMsg = append(serverMsg, authBuf...)
	if _, err := s.Write(serverMsg); err != nil {
		return fmt.Errorf("write server ticket: %w", err)
	}

	reply, err := readServerAuthenticator(s, clientTicket)
	if err != nil {
		return fmt.Errorf("read server authenticator: %w", err)
	}
	if reply.Num != dp9ik.AuthAs {
		return fmt.Errorf("unexpected server authenticator type %d", reply.Num)
	}
	if string(reply.Chal[:]) != string(cchal) {
		return fmt.Errorf("server authenticator challenge mismatch")
	}

	return nil
}

func readAuthServerTickets(conn net.Conn, clientKey *dp9ik.Authkey) (*dp9ik.Ticket, []byte, error) {
	limit := 2 * dp9ik.MAXTICKETLEN
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 256)
	var (
		clientTicket *dp9ik.Ticket
		ticketLen    int
	)

	for len(buf) <= limit {
		if clientTicket == nil && len(buf) > 0 {
			ticket, n, err := dp9ik.UnmarshalTicketWithLength(clientKey, buf)
			if err == nil {
				clientTicket = ticket
				ticketLen = n
				_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			}
		}

		n, err := conn.Read(chunk)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && clientTicket != nil {
				return clientTicket, append([]byte(nil), buf[ticketLen:]...), nil
			}
			if err == io.EOF && clientTicket != nil {
				return clientTicket, append([]byte(nil), buf[ticketLen:]...), nil
			}
			return nil, nil, err
		}
		if n == 0 {
			if clientTicket != nil {
				return clientTicket, append([]byte(nil), buf[ticketLen:]...), nil
			}
			continue
		}
		buf = append(buf, chunk[:n]...)
	}

	return nil, nil, fmt.Errorf("ticket response exceeded %d bytes", limit)
}

func readServerAuthenticator(r io.Reader, ticket *dp9ik.Ticket) (*dp9ik.Authenticator, error) {
	limit := dp9ik.MAXAUTHENTLEN
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 128)

	for len(buf) <= limit {
		if len(buf) > 0 {
			auth, _, err := dp9ik.UnmarshalAuthenticatorWithLength(ticket, buf)
			if err == nil {
				return auth, nil
			}
		}

		n, err := r.Read(chunk)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		buf = append(buf, chunk[:n]...)
	}

	return nil, fmt.Errorf("server authenticator exceeded %d bytes", limit)
}

type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecordingConn) Deadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]time.Time(nil), c.deadlines...)
}
