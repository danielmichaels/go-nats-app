package natsio

import (
	"encoding/json"
	"github.com/nats-io/nats.go"
	"{{ cookiecutter.go_module_path.strip() }}/internal/config"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"sync"
	"time"
)

type Nats struct {
	Conn    *nats.Conn
	EncConn *nats.EncodedConn
	once    sync.Once
}

func Encoder(v io.Reader, ptr interface{}) ([]byte, error) {
	d := json.NewDecoder(v)
	err := d.Decode(&ptr)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(ptr)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func Connect(name string) (*nats.Conn, error) {
	uri := config.AppConfig().Nats.URI
	opts := []nats.Option{nats.Name(name)}
	opts = setupConnOptions(opts)
	nc, err := nats.Connect(
		uri,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return nc, nil
}
func EConnect(nc *nats.Conn) (*nats.EncodedConn, error) {
	ec, err := nats.NewEncodedConn(nc, nats.JSON_ENCODER)
	if err != nil {
		return nil, err
	}
	return ec, nil
}

func setupConnOptions(opts []nats.Option) []nats.Option {
	totalWait := 10 * time.Minute
	reconnectDelay := time.Second
	pingInterval := 20 * time.Second
	maxPingOutstanding := 5
	timeout := 30 * time.Second

	opts = append(opts, nats.Timeout(timeout))
	opts = append(opts, nats.PingInterval(pingInterval))
	opts = append(opts, nats.MaxPingsOutstanding(maxPingOutstanding))
	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		log.Printf("Disconnected due to: %s, will attempt reconnects for %.0fm", err, totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		log.Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		log.Error().Msgf("Exiting: %v", nc.LastError())
		os.Exit(1)
	}))
	opts = append(opts, nats.DrainTimeout(10*time.Second))
	return opts
}
