package main

import (
	"github.com/go-chi/httplog"
	"{{ cookiecutter.go_module_path.strip() }}/internal/config"
	"{{ cookiecutter.go_module_path.strip() }}/internal/natsio"
	{% if cookiecutter.mongo == "y" %}
	"{{ cookiecutter.go_module_path.strip() }}/internal/db"
    "context"
	{% endif %}
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
)

func main() {
	err := run()
	if err != nil {
		log.Error().Err(err).Msgf("server failed to start: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.AppConfig()
	logger := httplog.NewLogger("{{ cookiecutter.project_slug.strip() }}", httplog.Options{
		JSON:     cfg.AppConf.LogJson,
		Concise:  cfg.AppConf.LogConcise,
		LogLevel: cfg.AppConf.LogLevel,
	})
	if cfg.AppConf.LogCaller {
		logger = logger.With().Caller().Logger()
	}
	natsConn, err := natsio.Connect(cfg.Nats.URI)
	if err != nil {
		return err
	}
	NatsEconn, err := natsio.EConnect(natsConn)
	if err != nil {
		return err
	}
	nc := natsio.Nats{Conn: natsConn, EncConn: NatsEconn}

	{% if cookiecutter.mongo == "y" %}
    dbConn, err := db.InitDatabase(cfg.Db.DbName)
	if err != nil {
		return err
	}
	{% endif %}

	app := natsio.Application{
		Nats:   &nc,
		Config: cfg,
		Logger: logger,
	{% if cookiecutter.mongo == "y" %}
	    Database: dbConn,
	{% endif %}
	}

	logger.Info().Msgf("NATS connected to: %q", cfg.Nats.URI)
	err = app.InitSubscribers()
	if err != nil {
		logger.Error().Err(err).Msg("error: failed to initialise subscribers")
		os.Exit(1)
	}
	// Set up the interrupt handler to drain, so we don't miss
	// requests when scaling down.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c // Block
	app.Logger.Info().Msg("Draining NATS")
	err = app.Nats.Conn.Drain()
	if err != nil {
		logger.Error().Err(err).Msg("error: failed to drain messages")
	}
	logger.Info().Msg("NATS connection shutdown")
	{% if cookiecutter.mongo == "y" %}
    err = app.Database.Client().Disconnect(context.TODO())
	if err != nil {
		logger.Error().Err(err).Msg("error: failed to disconnect from database")
	}
	logger.Info().Msg("database connection shutdown")
    {% endif %}
	return nil
}
