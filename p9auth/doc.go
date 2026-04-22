// Package p9auth provides reusable server-side 9P authentication helpers built
// on top of the dp9ik protocol package.
//
// It implements the server side of the p9any plus dp9ik exchange and can be
// used directly over an io.ReadWriter or adapted to go9p/fs.WithAuth.
package p9auth
