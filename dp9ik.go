package dp9ik

/*
#cgo CFLAGS: -I${SRCDIR}/drawterm/include -I${SRCDIR}/drawterm -I${SRCDIR}
#cgo LDFLAGS: ${SRCDIR}/drawterm/libauthsrv/libauthsrv.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libsec/libsec.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libmp/libmp.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libc/libc.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libmachdep.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libsec/libsec.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libmp/libmp.a
#cgo LDFLAGS: ${SRCDIR}/drawterm/libc/libc.a
#cgo LDFLAGS: ${SRCDIR}/libstubs.a
#cgo LDFLAGS: -lm -lpthread

#include <stdlib.h>
#include "drawterm_wrapper.h"
*/
import "C"
import (
	"sync"
	"unsafe"
)

// cgoMutex protects all CGo calls into drawterm's C libraries.
// This is necessary because:
// 1. genrandom() in libsec uses a static QLock that we stub as no-op
// 2. authpak_curve() uses a static Lock for lazy initialization
// By protecting all entry points at the Go level, we ensure thread safety
// even though the underlying C code uses stubbed locks.
var cgoMutex sync.Mutex

// The fixed-width protocol field lengths and authsrv message type constants
// match 9front's authsrv.h definitions.
const (
	ANAMELEN = 28
	DOMLEN   = 48
	CHALLEN  = 8
	NONCELEN = 32

	AuthTreq   = 1
	AuthChal   = 2
	AuthPass   = 3
	AuthOK     = 4
	AuthErr    = 5
	AuthMod    = 6
	AuthApop   = 7
	AuthOKvar  = 9
	AuthChap   = 10
	AuthMSchap = 11
	AuthCram   = 12
	AuthHttp   = 13
	AuthVNC    = 14
	AuthPAK    = 19

	AuthTs = 64
	AuthTc = 65
	AuthAs = 66
	AuthAc = 67
	AuthTp = 68
	AuthHr = 69

	TICKREQLEN = 141
)

// Ticketreq matches 9front's Ticketreq wire structure.
type Ticketreq struct {
	// Type is the authsrv message type carried by the request.
	Type byte
	// Authid is the server-side auth identity.
	Authid [ANAMELEN]byte
	// Authdom is the authentication domain.
	Authdom [DOMLEN]byte
	// Chal is the challenge carried in the request.
	Chal [CHALLEN]byte
	// Hostid is the requesting host identity.
	Hostid [ANAMELEN]byte
	// Uid is the end-user identity being authenticated.
	Uid [ANAMELEN]byte
}

// Compile-time size check
const _ = uint(unsafe.Sizeof(Ticketreq{})) - C.sizeof_struct_Ticketreq

// Marshal converts tr to authsrv wire format using the drawterm C
// implementation.
func (tr *Ticketreq) Marshal() ([]byte, error) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	var ctr C.struct_Ticketreq

	// Set type field
	*(*C.char)(unsafe.Pointer(&ctr)) = C.char(tr.Type)

	// Copy array fields
	copy((*[ANAMELEN]byte)(unsafe.Pointer(&ctr.authid))[:], tr.Authid[:])
	copy((*[DOMLEN]byte)(unsafe.Pointer(&ctr.authdom))[:], tr.Authdom[:])
	copy((*[CHALLEN]byte)(unsafe.Pointer(&ctr.chal))[:], tr.Chal[:])
	copy((*[ANAMELEN]byte)(unsafe.Pointer(&ctr.hostid))[:], tr.Hostid[:])
	copy((*[ANAMELEN]byte)(unsafe.Pointer(&ctr.uid))[:], tr.Uid[:])

	buf := make([]byte, TICKREQLEN)
	n := C.convTR2M(&ctr, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))

	if n <= 0 {
		return nil, &AuthError{Msg: "convTR2M failed"}
	}

	return buf[:n], nil
}

// UnmarshalTicketreq decodes a Ticketreq from authsrv wire format and returns
// the decoded value plus the number of bytes consumed.
func UnmarshalTicketreq(buf []byte) (*Ticketreq, int, error) {
	if len(buf) == 0 {
		return nil, 0, &AuthError{Msg: "empty Ticketreq buffer"}
	}

	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	tr := &Ticketreq{}
	ctr := (*C.struct_Ticketreq)(unsafe.Pointer(tr))

	ret := C.convM2TR((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), ctr)
	if ret <= 0 {
		return nil, int(ret), &AuthError{Msg: "convM2TR failed"}
	}

	return tr, int(ret), nil
}

// AuthError reports a protocol or cryptographic authentication failure.
type AuthError struct {
	// Msg is the human-readable authentication failure.
	Msg string
}

// Error returns the authentication failure message.
func (e *AuthError) Error() string {
	return e.Msg
}

// The dp9ik key, hash, and message size constants match 9front's authsrv.h
// definitions.
const (
	DESKEYLEN     = 7
	AESKEYLEN     = 16
	PAKKEYLEN     = 32
	PAKSLEN       = (448 + 7) / 8 // 56
	PAKPLEN       = 4 * PAKSLEN   // 224
	PAKHASHLEN    = 2 * PAKPLEN   // 448
	PAKXLEN       = PAKSLEN       // 56
	PAKYLEN       = PAKSLEN       // 56
	MAXTICKETLEN  = 12 + CHALLEN + 2*ANAMELEN + NONCELEN + 16
	MAXAUTHENTLEN = 12 + CHALLEN + NONCELEN + 16
)

// Ticket represents a decrypted server-issued ticket.
type Ticket struct {
	// Num is the ticket type, such as AuthTs or AuthTc.
	Num byte
	// Chal is the challenge bound to the ticket.
	Chal [CHALLEN]byte
	// Cuid is the client user identity carried in the ticket.
	Cuid [ANAMELEN]byte
	// Suid is the server user identity carried in the ticket.
	Suid [ANAMELEN]byte
	// Key is the session key established by the ticket.
	Key [NONCELEN]byte
	// Form records the key form locally and is not transmitted on the wire.
	Form byte // not transmitted, local only
}

// Authenticator represents a client or server authenticator message.
type Authenticator struct {
	// Num is the authenticator type, such as AuthAc or AuthAs.
	Num byte
	// Chal is the challenge echoed back to prove possession of the ticket key.
	Chal [CHALLEN]byte
	// Rand carries the authenticator nonce.
	Rand [NONCELEN]byte
}

// Authkey holds the derived DES, AES, and AuthPAK key material for a password.
type Authkey struct {
	// Des is the derived DES key.
	Des [DESKEYLEN]byte
	// Aes is the derived AES key.
	Aes [AESKEYLEN]byte
	// Pakkey is the derived AuthPAK key.
	Pakkey [PAKKEYLEN]byte
	// Pakhash is the derived AuthPAK password hash buffer.
	Pakhash [PAKHASHLEN]byte
}

// PAKpriv holds the local private state for an AuthPAK exchange.
type PAKpriv struct {
	// Isclient records whether the state was initialized for the client side.
	Isclient int32
	// X is the private scalar for the AuthPAK exchange.
	X [PAKXLEN]byte
	// Y is the public value generated for the AuthPAK exchange.
	Y [PAKYLEN]byte
}

// Compile-time size checks for all structs
const (
	_ = uint(unsafe.Sizeof(Ticket{})) - C.sizeof_struct_Ticket
	_ = uint(unsafe.Sizeof(Authenticator{})) - C.sizeof_struct_Authenticator
	_ = uint(unsafe.Sizeof(Authkey{})) - C.sizeof_struct_Authkey
	_ = uint(unsafe.Sizeof(PAKpriv{})) - C.sizeof_struct_PAKpriv
)

// PassToKey derives the dp9ik authentication key material for password.
func PassToKey(password string) (*Authkey, error) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	key := &Authkey{}
	ckey := (*C.struct_Authkey)(unsafe.Pointer(key))
	cpass := C.CString(password)
	defer C.free(unsafe.Pointer(cpass))

	C.passtokey(ckey, cpass)

	return key, nil
}

// AuthPAKHash derives the AuthPAK password hash for username.
func (k *Authkey) AuthPAKHash(username string) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))
	cuser := C.CString(username)
	defer C.free(unsafe.Pointer(cuser))

	C.authpak_hash(ckey, cuser)
}

// AuthPAKNew initializes a new AuthPAK exchange and returns the local public
// value to send to the peer.
func (p *PAKpriv) AuthPAKNew(k *Authkey, isClient bool) []byte {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	cp := (*C.struct_PAKpriv)(unsafe.Pointer(p))
	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))
	y := make([]byte, PAKYLEN)

	var isclient C.int
	if isClient {
		isclient = 1
	}

	C.authpak_new(cp, ckey, (*C.uchar)(unsafe.Pointer(&y[0])), isclient)

	return y
}

// AuthPAKFinish completes the AuthPAK exchange using the peer's public value.
func (p *PAKpriv) AuthPAKFinish(k *Authkey, peerY []byte) error {
	if len(peerY) != PAKYLEN {
		return &AuthError{Msg: "invalid peer Y length"}
	}

	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	cp := (*C.struct_PAKpriv)(unsafe.Pointer(p))
	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))

	ret := C.authpak_finish(cp, ckey, (*C.uchar)(unsafe.Pointer(&peerY[0])))

	if ret != 0 {
		return &AuthError{Msg: "authpak_finish failed"}
	}

	return nil
}

// UnmarshalTicketWithLength decrypts a ticket from buf and returns the decoded
// ticket plus the number of bytes consumed.
func UnmarshalTicketWithLength(k *Authkey, buf []byte) (*Ticket, int, error) {
	if len(buf) == 0 {
		return nil, 0, &AuthError{Msg: "empty ticket buffer"}
	}

	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	ticket := &Ticket{}
	cticket := (*C.struct_Ticket)(unsafe.Pointer(ticket))
	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))

	ret := C.convM2T((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), cticket, ckey)

	if ret <= 0 {
		return nil, int(ret), &AuthError{Msg: "convM2T failed"}
	}

	return ticket, int(ret), nil
}

// UnmarshalTicket decrypts and unmarshals a ticket from authsrv wire format.
func UnmarshalTicket(k *Authkey, buf []byte) (*Ticket, error) {
	ticket, _, err := UnmarshalTicketWithLength(k, buf)
	return ticket, err
}

// Marshal encrypts and marshals t to authsrv wire format using k.
func (t *Ticket) Marshal(k *Authkey) ([]byte, error) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	cticket := (*C.struct_Ticket)(unsafe.Pointer(t))
	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))

	buf := make([]byte, MAXTICKETLEN)
	n := C.convT2M(cticket, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), ckey)

	if n <= 0 {
		return nil, &AuthError{Msg: "convT2M failed"}
	}

	return buf[:n], nil
}

// UnmarshalAuthenticatorWithLength decrypts an authenticator from buf using
// the ticket key and returns the decoded value plus the number of bytes
// consumed.
func UnmarshalAuthenticatorWithLength(t *Ticket, buf []byte) (*Authenticator, int, error) {
	if len(buf) == 0 {
		return nil, 0, &AuthError{Msg: "empty authenticator buffer"}
	}

	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	auth := &Authenticator{}
	cauth := (*C.struct_Authenticator)(unsafe.Pointer(auth))
	cticket := (*C.struct_Ticket)(unsafe.Pointer(t))

	ret := C.convM2A((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), cauth, cticket)

	if ret <= 0 {
		return nil, int(ret), &AuthError{Msg: "convM2A failed"}
	}

	return auth, int(ret), nil
}

// UnmarshalAuthenticator decrypts and unmarshals an authenticator from authsrv
// wire format using the ticket key.
func UnmarshalAuthenticator(t *Ticket, buf []byte) (*Authenticator, error) {
	auth, _, err := UnmarshalAuthenticatorWithLength(t, buf)
	return auth, err
}

// Marshal encrypts and marshals a to authsrv wire format using the ticket key.
func (a *Authenticator) Marshal(t *Ticket) ([]byte, error) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	cauth := (*C.struct_Authenticator)(unsafe.Pointer(a))
	cticket := (*C.struct_Ticket)(unsafe.Pointer(t))

	buf := make([]byte, MAXAUTHENTLEN)
	n := C.convA2M(cauth, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), cticket)

	if n <= 0 {
		return nil, &AuthError{Msg: "convA2M failed"}
	}

	return buf[:n], nil
}
