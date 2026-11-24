// Package natsdev runs an embedded operator-mode NATS server for local
// development and tests. Deployments use an external server.
package natsdev

import (
	"errors"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"

	"{{ cookiecutter.go_module_path }}/internal/natsauth"
)

type Options struct {
	Host           string
	Port           int
	WebsocketPort  int
	AllowedOrigins []string
	StoreDir       string
}

type Server struct {
	*server.Server
	Runtime natsauth.Runtime
}

func Start(keys natsauth.Keys, o Options) (*Server, error) {
	srv, rt, err := keys.Build()
	if err != nil {
		return nil, err
	}
	op, err := jwt.DecodeOperatorClaims(srv.Operator)
	if err != nil {
		return nil, err
	}
	resolver := &server.MemAccResolver{}
	for pub, t := range srv.Accounts {
		if err := resolver.Store(pub, t); err != nil {
			return nil, err
		}
	}
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	opts := &server.Options{
		ServerName:       "app-dev",
		Host:             o.Host,
		Port:             o.Port,
		NoSigs:           true,
		NoLog:            true,
		JetStream:        true,
		StoreDir:         o.StoreDir,
		TrustedOperators: []*jwt.OperatorClaims{op},
		SystemAccount:    srv.SystemAccount,
		AccountResolver:  resolver,
	}
	if o.WebsocketPort != 0 {
		opts.Websocket = server.WebsocketOpts{
			Host:           o.Host,
			Port:           o.WebsocketPort,
			NoTLS:          true,
			AllowedOrigins: o.AllowedOrigins,
			SameOrigin:     false,
		}
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, err
	}
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return nil, errors.New("embedded NATS did not start")
	}
	return &Server{Server: ns, Runtime: rt}, nil
}

func (s *Server) Stop() {
	s.Shutdown()
	s.WaitForShutdown()
}
