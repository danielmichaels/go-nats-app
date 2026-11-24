package natsauth

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Creds authenticates with the JWT and seed of a creds file body.
func Creds(creds string) (nats.Option, error) {
	t, err := jwt.ParseDecoratedJWT([]byte(creds))
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.ParseDecoratedNKey([]byte(creds))
	if err != nil {
		return nil, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	return nats.UserJWTAndSeed(t, string(seed)), nil
}

// Sentinel presents the public bearer sentinel. The server does not check a
// signature for a bearer JWT, so no seed is needed.
func Sentinel(sentinel string) nats.Option {
	return nats.UserJWT(
		func() (string, error) { return sentinel, nil },
		func([]byte) ([]byte, error) { return []byte{}, nil },
	)
}
