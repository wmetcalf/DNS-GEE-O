# Repository Guidelines

## Project Structure & Module Organization
`cmd/dnsgeeo/main.go` is the CLI entry point. Core concurrency, enrichment, and cache code lives in `internal/dnsgeeo`. Binaries belong in `bin/`, GeoIP databases in `data/`, and worked examples (with supporting assets) in `examples/`. Keep experimental scripts out of the repo or tuck them under a clearly named subdirectory.

## Build, Test, and Development Commands
- `./install.sh`: compiles the CLI with Go ≥1.23 and, when `MAXMIND_LICENSE_KEY` is set, fetches GeoLite2 databases to `data/`.
- `go build -o ./bin/dnsgeeo ./cmd/dnsgeeo`: produces a platform-specific binary (drop it in `bin/` when distributing).
- `go run ./cmd/dnsgeeo --list "example.com"`: quick local smoke-test without installing.
- `go test ./... -race`: runs (future) unit tests across all packages with the race detector.

## Coding Style & Naming Conventions
Run `gofmt` (tabs) and `goimports` before committing; no manual spacing. Exported types/functions use PascalCase, locals use camelCase, and acronyms stay uppercase (`IP`, `DNS`). Option structs should be immutable after construction, and new APIs should accept `context.Context`. Leave a short comment when adding synchronization or caching logic that might surprise future readers.

## Testing Guidelines
Place `_test.go` files next to the code in `internal/dnsgeeo`. Prefer table-driven tests with seeded inputs so DNS and GeoIP paths stay deterministic. Cover success, lookup failures, timeouts, and cache eviction; target ≥80% statement coverage before promoting a PR. Use `go test ./... -run TestResolver -count=1` when focusing on a single suite without cached results.

## Commit & Pull Request Guidelines
This archive is often shared without `.git`, so follow Conventional Commits manually (e.g., `feat: add Quad9 toggle`, `fix: guard GeoIP cache`). Keep commits focused and include rationale when behavior changes. Pull requests must outline the scenario, list validation commands, call out new flags/env vars, and include screenshots or JSON snippets whenever CLI output changes. Link the relevant tracker item so downstream agents can trace intent.

## Security & Configuration Tips
Never commit licensed MaxMind databases; store paths in local `.env` files and pass them via `--city-db`/`--asn-db`. Sanitize demo data before publishing under `examples/`, and redact customer domains in documentation. Quad9 lookups default to `9.9.9.9`; override `--dns` only when policy requires an alternate resolver.
