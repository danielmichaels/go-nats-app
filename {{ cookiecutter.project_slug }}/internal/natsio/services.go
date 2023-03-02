package natsio

import (
	"github.com/nats-io/nats.go"
	"{{ cookiecutter.go_module_path.strip() }}/internal/config"
	"github.com/rs/zerolog"
	"time"
	{% if cookiecutter.mongo == "y" %}
	"go.mongodb.org/mongo-driver/mongo"
	{% endif %}
)

type Application struct {
	Nats   *Nats
	Config *config.Conf
	Logger zerolog.Logger
	{% if cookiecutter.mongo == "y" %}
	Database *mongo.Database
	{% endif %}
}

func (app *Application) InitSubscribers() error {
	err := app.exampleSubscriber()
	if err != nil {
		return err
	}
	err = app.exampleQueueGroup()
	if err != nil {
		return err
	}
	return nil
}

func (app *Application) exampleSubscriber() error {
	subj := "example.sub"
	if _, err := app.Nats.Conn.Subscribe(subj, func(msg *nats.Msg) {
		app.Logger.Debug().Msgf("%q msg.Data received: %-v", subj, string(msg.Data))
		time.Sleep(1 * time.Second)
	}); err != nil {
		app.Logger.Error().Err(err).Msgf("err subscribing to: %q", subj)
		return err
	}
	return nil
}

func (app *Application) exampleQueueGroup() error {
	subj := "example.queue"
	queue := "examples"
	if _, err := app.Nats.Conn.QueueSubscribe(subj, queue, func(msg *nats.Msg) {
		app.Logger.Debug().Msgf("%q msg.Data received: %-v", subj, string(msg.Data))
		time.Sleep(1 * time.Second)
	}); err != nil {
		app.Logger.Error().Err(err).Msgf("err subscribing to: %q", subj)
		return err
	}
	return nil
}
