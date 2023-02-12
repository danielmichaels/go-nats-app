package natsio

import (
	"github.com/nats-io/nats.go"
	"{{ cookiecutter.go_module_path.strip() }}/internal/config"
	"github.com/rs/zerolog"
	"time"

)

type Application struct {
	Nats   *Nats
	Config *config.Conf
	Logger zerolog.Logger
}

func (app *Application) InitSubscribers() error {
	err := app.exampleSubscriber1()
	if err != nil {
		return err
	}
	err = app.exampleSubscriber2()
	if err != nil {
		return err
	}
	return nil
}

func (app *Application) exampleSubscriber1() error {
	subj := "example.event.1"
	if _, err := app.Nats.Conn.Subscribe(subj, func(msg *nats.Msg) {
		app.Logger.Debug().Msgf("example.event.1 msg.Data received: %-v", string(msg.Data))
		time.Sleep(1 * time.Second)
	}); err != nil {
		app.Logger.Error().Err(err).Msgf("err subscribing to: %q", subj)
		return err
	}
	return nil
}

func (app *Application) exampleSubscriber2() error {
	subj := "example.event.2"
	if _, err := app.Nats.Conn.Subscribe(subj, func(msg *nats.Msg) {
		app.Logger.Debug().Msgf("example.event.2 msg.Data received: %-v", string(msg.Data))
		time.Sleep(1 * time.Second)
	}); err != nil {
		app.Logger.Error().Err(err).Msgf("err subscribing to: %q", subj)
		return err
	}
	return nil
}
