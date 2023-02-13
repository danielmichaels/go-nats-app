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

### Usage

To see this in action. Run the `nats-box` container locally and publish some messages whilst this
server is running.

```shell
# open two terminals
# in terminal one run:
air 

# in terminal two run:
docker run --rm -it synadia/nats-box 
# inside the container run
nats pub example.sub 'All subscribers will see this'
nats pub example.queue 'Only one subscriber per queue group would see this'
```

This demonstrates the concept of subscribers and queue groups. In a subscriber model every subscriber
will see and consume that message. Whereas, in a queue group no matter how many consumers there are
only one will receive the message. Which you choose is up to you.
