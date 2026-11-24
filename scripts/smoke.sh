#!/usr/bin/env bash
# Generates a project for one frontend with a non-default name and module
# path, then checks, tests and builds it.
# usage: scripts/smoke.sh <datastar|react> [outdir]
set -euo pipefail
frontend=$1
out=${2:-$(mktemp -d)}
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT
# Copy the committed template only, so local node_modules and builds stay out.
git -C "$repo" ls-files -z | (cd "$repo" && xargs -0 tar -cf -) | tar -C "$src" -xf -

cookiecutter --no-input -f -o "$out" "$src" \
  frontend="$frontend" project_name="Acme Notes" github_username=acme >/dev/null
cd "$out/acme-notes"
grep -q '^module github.com/acme/acme-notes$' go.mod

case $frontend in
datastar)
  test ! -e web && test ! -e internal/spa
  go run github.com/a-h/templ/cmd/templ@v0.3.1118 generate
  ;;
react)
  test ! -e internal/htmlui
  (cd web && pnpm install --frozen-lockfile && pnpm typecheck && pnpm build)
  test -f internal/spa/dist/index.html
  ;;
esac

test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
go build -o /dev/null ./cmd/app
echo "smoke $frontend: ok ($out/acme-notes)"
