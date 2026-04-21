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

// Ticketreq matches the C struct Ticketreq
type Ticketreq struct {
	Type    byte
	Authid  [ANAMELEN]byte
	Authdom [DOMLEN]byte
	Chal    [CHALLEN]byte
	Hostid  [ANAMELEN]byte
	Uid     [ANAMELEN]byte
}

// Compile-time size check
const _ = uint(unsafe.Sizeof(Ticketreq{})) - C.sizeof_struct_Ticketreq

// Marshal converts Ticketreq to wire format using C implementation
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

// UnmarshalTicketreq decodes a Ticketreq from wire format.
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

// AuthError represents an authentication error
type AuthError struct {
	Msg string
}

func (e *AuthError) Error() string {
	return e.Msg
}

// Additional constants from authsrv.h
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

// Ticket represents a server-issued ticket
type Ticket struct {
	Num  byte
	Chal [CHALLEN]byte
	Cuid [ANAMELEN]byte
	Suid [ANAMELEN]byte
	Key  [NONCELEN]byte
	Form byte // not transmitted, local only
}

// Authenticator for client/server authentication
type Authenticator struct {
	Num  byte
	Chal [CHALLEN]byte
	Rand [NONCELEN]byte
}

// Authkey holds all key material
type Authkey struct {
	Des     [DESKEYLEN]byte
	Aes     [AESKEYLEN]byte
	Pakkey  [PAKKEYLEN]byte
	Pakhash [PAKHASHLEN]byte
}

// PAKpriv holds private state for AuthPAK exchange
type PAKpriv struct {
	Isclient int32
	X        [PAKXLEN]byte
	Y        [PAKYLEN]byte
}

// Compile-time size checks for all structs
const (
	_ = uint(unsafe.Sizeof(Ticket{})) - C.sizeof_struct_Ticket
	_ = uint(unsafe.Sizeof(Authenticator{})) - C.sizeof_struct_Authenticator
	_ = uint(unsafe.Sizeof(Authkey{})) - C.sizeof_struct_Authkey
	_ = uint(unsafe.Sizeof(PAKpriv{})) - C.sizeof_struct_PAKpriv
)

// PassToKey converts password to authentication key
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

// AuthPAKHash derives the hash for AuthPAK
func (k *Authkey) AuthPAKHash(username string) {
	cgoMutex.Lock()
	defer cgoMutex.Unlock()

	ckey := (*C.struct_Authkey)(unsafe.Pointer(k))
	cuser := C.CString(username)
	defer C.free(unsafe.Pointer(cuser))

	C.authpak_hash(ckey, cuser)
}

// AuthPAKNew initializes AuthPAK exchange
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

// AuthPAKFinish completes AuthPAK exchange
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

// UnmarshalTicketWithLength decrypts a ticket and returns the number of bytes consumed.
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

// UnmarshalTicket decrypts and unmarshals a ticket from wire format.
func UnmarshalTicket(k *Authkey, buf []byte) (*Ticket, error) {
	ticket, _, err := UnmarshalTicketWithLength(k, buf)
	return ticket, err
}

// MarshalTicket encrypts and marshals a ticket to wire format
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

// UnmarshalAuthenticatorWithLength decrypts an authenticator and returns the number of bytes consumed.
// Uses the ticket's key field for decryption.
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

// UnmarshalAuthenticator decrypts and unmarshals an authenticator from wire format.
// Uses the ticket's key field for decryption.
func UnmarshalAuthenticator(t *Ticket, buf []byte) (*Authenticator, error) {
	auth, _, err := UnmarshalAuthenticatorWithLength(t, buf)
	return auth, err
}

// Marshal encrypts and marshals an authenticator to wire format
// Uses the ticket's key field for encryption
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
