# go-dp9ik

Go library for 9front dp9ik authentication (AuthPAK/SPAKE2-EE on Ed448) using CGo with drawterm's battle-tested crypto implementation.

The repository now has two reusable layers:

- `dp9ik`: low-level protocol, crypto, and wire-format primitives
- `p9auth`: reusable server-side `p9any` + `dp9ik` verifier for 9P services

It is still **not** a standalone 9front auth server and does not replace the auth server itself.

## Installation

```bash
go get github.com/kiljoy001/go-dp9ik
```

## Building

The library includes C source files from drawterm that need to be compiled first:

```bash
# Build C libraries (pre-built .a files included for convenience)
make

# Or build Go package directly (uses pre-built libraries)
go build
```

## Usage

This repository is for applications that need to speak `dp9ik` or verify `dp9ik` authentication for 9P services. Use cases include:

- custom Plan 9 clients written in Go
- tools that need to obtain authentication tickets from 9front
- 9P services that need to require 9front auth before `attach`

```go
import "github.com/kiljoy001/go-dp9ik"

// Client-side authentication to a 9front auth server
key, err := dp9ik.PassToKey(password)
if err != nil {
    return err
}

// Generate AuthPAK hash for username
key.AuthPAKHash(username)

// Connect to auth server and perform AuthPAK exchange
// See dp9ik_test.go TestAuthPAKFullFlow for complete example
```

For a reusable server-side verifier:

```go
import "github.com/kiljoy001/go-dp9ik/p9auth"

auth := p9auth.AuthFunc(p9auth.Config{
    Domain:   "rentonsoftworks.coin",
    User:     "scott",
    Password: "REDACTED_TEST_PASSWORD",
})

// Example: pass auth to a 9P server hook such as go9p/fs.WithAuth(auth)
```

## Testing

This library is developed using TDD against a live 9front auth server.

```bash
go test -v
```

### Test Coverage

**Happy Path Tests:**
- [x] Server connectivity
- [x] Server responsiveness
- [x] Ticketreq wire format
- [x] C implementation compatibility
- [x] Password derivation (passtokey)
- [x] AuthPAK key exchange
- [x] Full authentication flow ✓
- [x] Struct size validation

**Unhappy Path Tests:**
- [x] Invalid server address
- [x] Wrong password handling
- [x] Invalid Y length rejection
- [x] Empty username handling
- [x] Connection timeout
- [x] Server disconnect during AuthPAK
- [x] Compile-time size checks

**Additional Tests:**
- [x] Concurrent authentication (thread safety)
- [x] Complete AuthPAK flow
- [x] Ticket marshaling/unmarshaling
- [x] Authenticator marshaling/unmarshaling
- [x] Server-side `p9any` + `dp9ik` verifier handshake
- [x] Wrong-password rejection for server-side verifier

**Result:** root package and `p9auth` package tests pass, including live-auth-server coverage.

## Architecture

### CGo Wrappers
- Uses drawterm's C implementation via CGo
- Wraps `libauthsrv.a`, `libsec.a`, `libmp.a`, `libc.a`
- All cryptography from proven Plan 9 code
- Minimal kernel stubs for POSIX compatibility

### Implemented Features

**Wire Protocol:**
- Ticketreq (AuthPAK type 19 and AuthTreq type 1)
- Ticket encryption/decryption (Form0 DES + Form1 ChaCha20-Poly1305)
- Authenticator encryption/decryption

**Cryptographic Operations:**
- Password-based key derivation (passtokey)
- AuthPAK (SPAKE2-EE on Ed448 Goldilocks curve)
- Shared secret establishment via ECDH

**Authentication Flow:**
- Complete dp9ik/AuthPAK handshake
- Ticket marshaling/unmarshaling (convT2M, convM2T)
- Authenticator marshaling/unmarshaling (convA2M, convM2A)
- Reusable server-side `p9any` negotiation + `dp9ik` verification for 9P auth files

**Thread Safety:**
- Go mutex protects all CGo calls to C libraries
- Safe for concurrent use from multiple goroutines
- Tested with 10 simultaneous authentication flows

## Protocol Details

The dp9ik (AuthPAK) protocol implements password-authenticated key exchange using SPAKE2-EE on the Ed448 Goldilocks elliptic curve:

1. Client derives key from password using Plan 9's passtokey
2. Client generates AuthPAK hash for username
3. Client sends Ticketreq (type 19 = AuthPAK) + 9P server's Y value
4. Client generates its own Y value and sends to auth server
5. Auth server responds with AuthOK + 2×PAKYLEN bytes (server Y + finish data)
6. Client completes AuthPAK with authpak_finish to establish shared key
7. Client sends AuthTreq (type 1) to request tickets
8. Server responds with encrypted tickets

## Files and Structure

```
go-dp9ik/
├── dp9ik.go              # Main library implementation
├── dp9ik_test.go         # Comprehensive test suite
├── p9auth/
│   ├── p9auth.go         # Reusable server-side verifier
│   └── p9auth_test.go    # Server-side verifier tests
├── struct_sizes_test.go  # Compile-time struct validation
├── stubs.c               # POSIX compatibility stubs
├── Makefile              # Build system for C libraries
└── drawterm/             # C source from drawterm
    ├── include/          # Header files
    ├── libc/             # Plan 9 C library
    ├── libmp/            # Multi-precision arithmetic
    ├── libsec/           # Cryptography (Ed448, ChaCha20, etc.)
    ├── libauthsrv/       # Authentication protocol
    └── posix-port/       # POSIX-specific implementations
```

## License

This code wraps and links against drawterm's Plan 9 libraries. Consult drawterm's license for details.

## Development

This library was developed through LLM-assisted programming, using Claude Code to generate CGo wrappers and test infrastructure around existing battle-tested C implementations from drawterm. The development process involved:

- Analyzing drawterm's C source code to understand protocol implementation
- Creating CGo bindings to expose Plan 9 authentication functions to Go
- Writing comprehensive tests against a live 9front authentication server
- Implementing thread safety through Go mutexes protecting C library calls
- Debugging protocol flows by studying actual network interactions
- Extracting a reusable server-side verifier for `p9any` + `dp9ik`

All cryptographic implementations and protocol logic come from drawterm's proven C code. The LLM contribution was the Go wrapper layer, build system, and test suite.

## Credits

- Cryptographic implementation from [drawterm](https://github.com/9front/drawterm)
- AuthPAK protocol from 9front
- CGo wrappers and tests developed with Claude Code
- Test-driven development against live 9front authentication server
