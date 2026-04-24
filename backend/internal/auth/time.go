package auth

import "time"

// nowUTC is overridable in tests — every production caller reads the
// real wall clock. Declared in its own file to avoid cluttering totp.go
// with a test seam.
var nowUTC = func() time.Time { return time.Now().UTC() }
