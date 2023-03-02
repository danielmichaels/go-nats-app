package config

import (
	"github.com/joeshaw/envdecode"
	"log"
)

{% if cookiecutter.mongo == "y" %}
type Conf struct {
	Db      dbConf
	AppConf appConf
	Nats    nats
}
{% else %}
type Conf struct {
	AppConf appConf
	Nats    nats
}
{% endif %}


{%- if cookiecutter.mongo == "y" -%}
type dbConf struct {
	DbName             string `env:"DATABASE_NAME,default=openrecce"`
	DbNameAuth         string `env:"DATABASE_NAME,default=admin"`
	DbUsername         string `env:"DATABASE_USERNAME,default=root"`
	DbPassword         string `env:"DATABASE_PASSWORD,default=root"`
	DbConnectionString string `env:"DATABASE_CONNECTION_STRING,default=mongodb.services"`
	DbPort             int    `env:"DATABASE_PORT,default=27017"`
}
{% endif %}

type appConf struct {
	LogLevel           string `env:"LOG_LEVEL,default=info"`
	LogConcise         bool   `env:"LOG_CONCISE,default=true"`
	LogJson            bool   `env:"LOG_JSON,default=false"`
	LogCaller          bool   `env:"LOG_CALLER,default=false"`
}

type nats struct {
	URI string `env:"NATS_URI,default=nats://0.0.0.0:4222/"`
}

// AppConfig Setup and install the applications' configuration environment variables
func AppConfig() *Conf {
	var c Conf
	if err := envdecode.StrictDecode(&c); err != nil {
		log.Fatalf("Failed to decode: %s", err)
	}
	return &c
}
