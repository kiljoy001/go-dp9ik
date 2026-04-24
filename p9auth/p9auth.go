package p9auth

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	dp9ik "github.com/kiljoy001/go-dp9ik"
)

const (
	maxP9AnyMessage         = 4096
	handshakeTimeout        = 5 * time.Second
	maxConsecutiveEmptyRead = 8
	minTicketMessageLen     = 1 + dp9ik.CHALLEN + 2*dp9ik.ANAMELEN + dp9ik.NONCELEN
	minAuthenticatorMsgLen  = 1 + dp9ik.CHALLEN + dp9ik.NONCELEN
)

type deadliner interface {
	SetDeadline(time.Time) error
}

type bufferedReader interface {
	io.Reader
	ReadSlice(byte) ([]byte, error)
}

// Config describes the server-side 9front auth key used to verify clients.
type Config struct {
	// Domain is the auth domain offered during p9any negotiation.
	Domain string
	// User is the auth identity used to derive the server key.
	User string
	// Password is the auth password used to derive the server key.
	Password string
}

// Validate reports whether the server-side auth configuration is complete.
func (c Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("missing domain")
	}
	if c.User == "" {
		return fmt.Errorf("missing user")
	}
	if c.Password == "" {
		return fmt.Errorf("missing password")
	}
	return nil
}

// AuthFunc adapts Handshake to go9p/fs.WithAuth and similar hooks.
//
// If rw supports SetDeadline, the returned function applies a bounded
// handshake timeout automatically. Callers using transports without SetDeadline
// support must enforce their own read and write deadlines externally.
func AuthFunc(cfg Config) func(io.ReadWriter) (string, error) {
	return func(rw io.ReadWriter) (string, error) {
		return Handshake(rw, cfg)
	}
}

// Handshake runs the server side of the p9any plus dp9ik auth-file exchange
// and returns the authenticated user on success.
//
// If rw supports SetDeadline, Handshake applies a temporary handshake deadline
// and clears it before returning. Callers using transports without SetDeadline
// support must enforce deadlines themselves before invoking Handshake.
//
// TODO: Add a context-aware Handshake variant for callers that need
// cancellation independent of transport deadlines.
func Handshake(rw io.ReadWriter, cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if d, ok := rw.(deadliner); ok {
		if err := d.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			return "", fmt.Errorf("set handshake deadline: %w", err)
		}
		defer func() {
			_ = d.SetDeadline(time.Time{})
		}()
	}
	reader := ensureBufferedReader(rw)

	key, err := dp9ik.PassToKey(cfg.Password)
	if err != nil {
		return "", fmt.Errorf("derive server key: %w", err)
	}
	key.AuthPAKHash(cfg.User)

	if err := writeCString(rw, fmt.Sprintf("dp9ik@%s", cfg.Domain)); err != nil {
		return "", fmt.Errorf("write p9any offer: %w", err)
	}

	choice, err := readCString(reader, maxP9AnyMessage)
	if err != nil {
		return "", fmt.Errorf("read p9any choice: %w", err)
	}
	parts := strings.Fields(choice)
	if len(parts) != 2 || parts[0] != "dp9ik" || parts[1] != cfg.Domain {
		return "", fmt.Errorf("unsupported auth choice %q", choice)
	}

	cchal, err := readFixed(reader, dp9ik.CHALLEN)
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

	clientY, err := readFixed(reader, dp9ik.PAKYLEN)
	if err != nil {
		return "", fmt.Errorf("read client pak y: %w", err)
	}
	if err := pak.AuthPAKFinish(key, clientY); err != nil {
		return "", fmt.Errorf("finish authpak: %w", err)
	}

	ticket, auth, err := readClientTicketAndAuthenticator(reader, key)
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
	reader := ensureBufferedReader(r)
	var (
		ticket     *dp9ik.Ticket
		ticketLen  int
		emptyReads int
	)

	for len(buf) <= limit {
		if ticket == nil && len(buf) >= minTicketMessageLen {
			decodedTicket, decodedLen, ticketErr := dp9ik.UnmarshalTicketWithLength(key, buf)
			if ticketErr == nil {
				ticket = decodedTicket
				ticketLen = decodedLen
			}
		}
		if ticket != nil && len(buf[ticketLen:]) >= minAuthenticatorMsgLen {
			auth, _, authErr := dp9ik.UnmarshalAuthenticatorWithLength(ticket, buf[ticketLen:])
			if authErr == nil {
				return ticket, auth, nil
			}
		}

		n, err := reader.Read(chunk)
		if err != nil {
			return nil, nil, err
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= maxConsecutiveEmptyRead {
				return nil, nil, fmt.Errorf("client auth message stalled after %d empty reads", maxConsecutiveEmptyRead)
			}
			continue
		}
		emptyReads = 0
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
	reader := ensureBufferedReader(r)
	var out bytes.Buffer

	for out.Len() < limit {
		chunk, err := reader.ReadSlice(0)
		switch {
		case err == nil:
			if out.Len()+len(chunk)-1 >= limit {
				return "", fmt.Errorf("p9any message exceeded %d bytes", limit)
			}
			out.Write(chunk[:len(chunk)-1])
			return out.String(), nil
		case errors.Is(err, bufio.ErrBufferFull):
			if out.Len()+len(chunk) >= limit {
				return "", fmt.Errorf("p9any message exceeded %d bytes", limit)
			}
			out.Write(chunk)
		default:
			return "", err
		}
	}

	return "", fmt.Errorf("p9any message exceeded %d bytes", limit)
}

func ensureBufferedReader(r io.Reader) bufferedReader {
	if reader, ok := r.(bufferedReader); ok {
		return reader
	}
	return bufio.NewReader(r)
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
