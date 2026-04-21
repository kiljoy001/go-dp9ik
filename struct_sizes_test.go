package dp9ik

import (
	"testing"
	"unsafe"
)

func TestAllStructSizes(t *testing.T) {
	tests := []struct {
		name     string
		goSize   uintptr
		expected int
	}{
		{"Ticketreq", unsafe.Sizeof(Ticketreq{}), 141},
		{"Ticket", unsafe.Sizeof(Ticket{}), 1 + CHALLEN + 2*ANAMELEN + NONCELEN + 1},
		{"Authenticator", unsafe.Sizeof(Authenticator{}), 1 + CHALLEN + NONCELEN},
		{"Authkey", unsafe.Sizeof(Authkey{}), DESKEYLEN + AESKEYLEN + PAKKEYLEN + PAKHASHLEN},
		{"PAKpriv", unsafe.Sizeof(PAKpriv{}), 4 + PAKXLEN + PAKYLEN},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goSize != uintptr(tt.expected) {
				t.Errorf("%s size mismatch: Go=%d, expected=%d", 
					tt.name, tt.goSize, tt.expected)
			}
			t.Logf("✓ %s: %d bytes", tt.name, tt.goSize)
		})
	}
}
