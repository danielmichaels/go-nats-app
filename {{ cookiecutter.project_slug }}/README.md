# {{ cookiecutter.project_name.strip() }}

> {{ cookiecutter.project_description.strip() }}

## Server setup

To run the server:

```shell
air
# OR
# make run/development
```

## Requirements

This expects at least the following:

- [nats-io](https://github.com/nats-io/nats.go)

The rest will be installed during `go mod tidy`.
