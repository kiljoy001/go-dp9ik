package p9auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strings"

	dp9ik "github.com/kiljoy001/go-dp9ik"
)

const maxP9AnyMessage = 4096

// Config describes the server-side 9front auth key used to verify clients.
type Config struct {
	Domain   string
	User     string
	Password string
}

// Validate checks whether the server-side auth configuration is complete.
func (c Config) Validate() error {
	if c.Domain == "" || c.User == "" || c.Password == "" {
		return fmt.Errorf("domain, user, and password are required")
	}
	return nil
}

// AuthFunc adapts Handshake to go9p/fs.WithAuth and similar hooks.
func AuthFunc(cfg Config) func(io.ReadWriter) (string, error) {
	return func(rw io.ReadWriter) (string, error) {
		return Handshake(rw, cfg)
	}
}

// Handshake runs the server side of the p9any + dp9ik auth-file exchange and
// returns the authenticated user on success.
func Handshake(rw io.ReadWriter, cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	key, err := dp9ik.PassToKey(cfg.Password)
	if err != nil {
		return "", fmt.Errorf("derive server key: %w", err)
	}
	key.AuthPAKHash(cfg.User)

	if err := writeCString(rw, fmt.Sprintf("dp9ik@%s", cfg.Domain)); err != nil {
		return "", fmt.Errorf("write p9any offer: %w", err)
	}

	choice, err := readCString(rw, maxP9AnyMessage)
	if err != nil {
		return "", fmt.Errorf("read p9any choice: %w", err)
	}
	parts := strings.Fields(choice)
	if len(parts) != 2 || parts[0] != "dp9ik" || parts[1] != cfg.Domain {
		return "", fmt.Errorf("unsupported auth choice %q", choice)
	}

	cchal, err := readFixed(rw, dp9ik.CHALLEN)
	if err != nil {
		return "", fmt.Errorf("read client challenge: %w", err)
	}

	var schal [dp9ik.CHALLEN]byte
	if _, err := rand.Read(schal[:]); err != nil {
		return "", fmt.Errorf("generate server challenge: %w", err)
	}

	tr := &dp9ik.Ticketreq{Type: dp9ik.AuthPAK}
	copy(tr.Authid[:], []byte(cfg.User))
	copy(tr.Authdom[:], []byte(cfg.Domain))
	copy(tr.Chal[:], schal[:])

	trbuf, err := tr.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal ticket request: %w", err)
	}

	pak := &dp9ik.PAKpriv{}
	serverY := pak.AuthPAKNew(key, true)

	offer := make([]byte, 0, len(trbuf)+len(serverY))
	offer = append(offer, trbuf...)
	offer = append(offer, serverY...)
	if _, err := rw.Write(offer); err != nil {
		return "", fmt.Errorf("write dp9ik offer: %w", err)
	}

	clientY, err := readFixed(rw, dp9ik.PAKYLEN)
	if err != nil {
		return "", fmt.Errorf("read client pak y: %w", err)
	}
	if err := pak.AuthPAKFinish(key, clientY); err != nil {
		return "", fmt.Errorf("finish authpak: %w", err)
	}

	ticket, auth, err := readClientTicketAndAuthenticator(rw, key)
	if err != nil {
		return "", fmt.Errorf("read client ticket: %w", err)
	}
	if ticket.Num != dp9ik.AuthTs {
		return "", fmt.Errorf("unexpected server ticket type %d", ticket.Num)
	}
	if subtle.ConstantTimeCompare(ticket.Chal[:], schal[:]) != 1 {
		return "", fmt.Errorf("server ticket challenge mismatch")
	}
	if auth.Num != dp9ik.AuthAc {
		return "", fmt.Errorf("unexpected client authenticator type %d", auth.Num)
	}
	if subtle.ConstantTimeCompare(auth.Chal[:], schal[:]) != 1 {
		return "", fmt.Errorf("client authenticator challenge mismatch")
	}

	reply := &dp9ik.Authenticator{Num: dp9ik.AuthAs}
	copy(reply.Chal[:], cchal)
	if _, err := rand.Read(reply.Rand[:]); err != nil {
		return "", fmt.Errorf("generate server nonce: %w", err)
	}

	replyBuf, err := reply.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("marshal server authenticator: %w", err)
	}
	if _, err := rw.Write(replyBuf); err != nil {
		return "", fmt.Errorf("write server authenticator: %w", err)
	}

	user := trimFixedString(ticket.Cuid[:])
	if user == "" {
		return "", fmt.Errorf("authenticated user is empty")
	}
	return user, nil
}

func readClientTicketAndAuthenticator(r io.Reader, key *dp9ik.Authkey) (*dp9ik.Ticket, *dp9ik.Authenticator, error) {
	limit := dp9ik.MAXTICKETLEN + dp9ik.MAXAUTHENTLEN
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 256)

	for len(buf) <= limit {
		if len(buf) > 0 {
			ticket, ticketLen, ticketErr := dp9ik.UnmarshalTicketWithLength(key, buf)
			if ticketErr == nil {
				auth, _, authErr := dp9ik.UnmarshalAuthenticatorWithLength(ticket, buf[ticketLen:])
				if authErr == nil {
					return ticket, auth, nil
				}
			}
		}

		n, err := r.Read(chunk)
		if err != nil {
			return nil, nil, err
		}
		if n == 0 {
			continue
		}
		buf = append(buf, chunk[:n]...)
	}

	return nil, nil, fmt.Errorf("client auth message exceeded %d bytes", limit)
}

func readFixed(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func readCString(r io.Reader, limit int) (string, error) {
	var out bytes.Buffer
	var b [1]byte

	for out.Len() < limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return out.String(), nil
		}
		out.WriteByte(b[0])
	}

	return "", fmt.Errorf("p9any message exceeded %d bytes", limit)
}

func writeCString(w io.Writer, value string) error {
	buf := make([]byte, len(value)+1)
	copy(buf, value)
	_, err := w.Write(buf)
	return err
}

func trimFixedString(buf []byte) string {
	if idx := bytes.IndexByte(buf, 0); idx >= 0 {
		buf = buf[:idx]
	}
	return string(bytes.TrimSpace(buf))
}
