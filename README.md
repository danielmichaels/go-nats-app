# go-nats-apapapapp [cookiecutter](https://cookiecutter.readthedocs.io/en/stable/) for quickly scaffolding go applications

This is a **highly** opinionated way of creating a Go service app using [NATS]. After manually
creating these time and time again this is how I've settled on bootstrapping
new app's. 

## Usage

To create a new go-nats-app using this repository you only need to run the following:

```shell
cookiecutter https://github.com/danielmichaels/go-web-app
# or gh:danielmichaels/go-web-app
```
And then answer the prompts. Here's an example run using the defaults:

```shell
z ❯ cookiecutter https://github.com/danielmichaels/go-nats-app
github_username [danielmichaels]: 
project_name [go-nats-app]: 
project_slug [go-nats-app]: 
cmd_name [app]: 
project_description [A service based application using NATS for messaging]: 
go_module_path [github.com/danielmichaels/go-nats-app]: 
Select go_version:
1 - 1.20
2 - 1.19
3 - 1.18
Choose from 1, 2, 3 [1]: 
```

This will create a directory called `go-nats-app` in the current working directory. All upper case
letters are converted to lowercase and hypens are used instead of spaces.

After `cookiecutter` has run the following output will be printed to the screen detailing
what to do next.

```shell
====================================================================================
Your project `go-web-app` is ready!
The following is a *brief* overview of steps to push code to remote and
how to get your go module working.
- Move to project directory, and initialize a git repository:
    $ cd go-web-app && git init
- Run go mod tidy to pull in dependencies:
    $ go mod tidy
- If you want to update upstream dependencies (optional; recommended)
    $ go get -u
- Create node resources (Tailwind and Alpine.js)
    $ yarn
    $ make assets
- Check the code works (if you have `air` in your $PATH)
    $ air
    or:
    $ go run cmd/app/main.go
    or:
    $ make run/app
- Upload initial code to git:
    $ git add -a
    $ git commit -m "Initial commit!"
    $ git remote add origin https://github.com/danielmichaels/go-web-app.git
    $ git push -u origin --all
```

[nats]: https://nats.io
