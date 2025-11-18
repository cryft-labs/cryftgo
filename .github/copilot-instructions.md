# GitHub Copilot Instructions for `cryftgo`

## Project Overview
- **Purpose**: `cryftgo` is the Go implementation of a Cryft network node, including consensus, networking, APIs, VM/plugin infrastructure, and integration with a separate `cryftee` runtime sidecar.
- **Entry point**: The main binary is in `main/main.go`; build scripts produce the `cryftgo` executable in `build/`.
- **Key domains**:
  - `snow/` – consensus and engine logic (Avalanche-style Snow/Snowman protocols).
  - `platformvm/` – validator set, staking, rewards, governance, and chain-level RPCs.
  - `genesis/` – network genesis config, including `genesis_pins.json` for initial IPFS pin requirements.
  - `api/` – HTTP/JSON-RPC APIs (admin, health, info, keystore, metrics, etc.).
  - `config/` – node configuration structs, CLI flag wiring, and documentation.
  - `database/` – pluggable DB backends (memdb, leveldb, pebble, merkledb, etc.).
  - `tests/` – unit tests plus e2e, antithesis, and fixture-based temporary networks.

## Build & Run Workflow
- **Build from source**:
  - Run `./scripts/build.sh` from repo root to produce `build/cryftgo`.
  - The entrypoint binary is `./build/cryftgo` (or via Docker using `./scripts/build_image.sh`).
- **Common run modes**:
  - Mainnet: `./build/cryftgo`.
  - Mustang testnet: `./build/cryftgo --network-id=mustang`.
- **Code generation**:
  - Protobuf: `scripts/protobuf_codegen.sh` (requires buf + protoc plugins, see `README.md`).
  - Mocks: `scripts/mock.gen.sh` (driven by `scripts/mock.mockgen.txt`).

## Testing & Fixtures
- **Unit/integration tests**:
  - Use `go test ./...` from repo root or targeted packages.
  - Many packages provide `Test*` helpers (for example, `snow/engine/.../test_*` files) that should be reused when adding tests.
- **Temporary networks**:
  - `tests/fixture/tmpnet/` orchestrates local multi-node networks; see its `README.md` for `Network`, `Node`, and config flows.
- **Antithesis tests**:
  - `tests/antithesis/` defines chaos-style workloads and docker-compose generators; mirror existing setups when extending.

## Architectural Patterns
- **Layered design**:
  - Core consensus/engine lives under `snow/` and `chains/`, decoupled from networking, storage, and APIs.
  - APIs in `api/` are thin JSON-RPC/HTTP layers over internal services and clients (for example, `api/info/service.md`, `api/admin/client.go`).
  - VM/plugin code in `vms/` is loaded via `--plugin-dir` and documented under `build/vm/` as referenced from `config/config.md`.
- **Runtime pinning via Cryftee**:
  - There is **no in-process middleware** in `cryftgo` for runtime/pin checking.
  - A separate sidecar project `cryftee` (outside this repo) is responsible for:
    - Reading `genesis/genesis_pins.json`-compatible configs.
    - Monitoring IPFS pin state and producing signed `RuntimeInfo` over HTTP.
  - `cryftgo` should only consume Cryftee over HTTP (for example, via a `RuntimeInfoClient`) and surface results via the Info/API layer; do not add middleware-style hooks into consensus or block processing.
- **Interfaces and test doubles**:
  - Subsystems expose interfaces in their top-level package (for example, `database.Database`, `indexer.Indexer`, `snow/engine/.../Manager`) with `mock_*` or `test_*` implementations alongside.
  - When adding new behavior, prefer extending existing interfaces and mocks instead of introducing ad-hoc concrete types.
- **Configuration wiring**:
  - Config structs and flags live in `config/config.go`, `config/flags.go`, and `config/viper.go`.
  - New settings (for example, Cryftee endpoint/timeout toggles) should be added to these structs, exposed as CLI flags, and documented in `config/config.md`.

## Conventions & Style
- **Go version & tooling**:
  - Target Go version is >= 1.21.10 as per `README.md` and `go.mod`.
  - Follow existing import grouping and naming (`ids`, `snow`, `vms`, etc.).
- **Testing conventions**:
  - Tests use `testing` plus `github.com/stretchr/testify/require`; follow patterns like `require.NoError`, `require.Equal`.
  - The repo has PRs banning `nil` in `require` assertions; use more precise checks instead.
- **Error handling & logging**:
  - Use shared logging utilities under `utils/logging` and honor config-driven log levels/format (`--log-level`, `--log-format`, etc.).

## APIs, Genesis, and Cryftee Integration
- **Node APIs**:
  - API definitions and documentation live under `api/*` (for example, `api/info/service.md`).
  - When adding or updating methods (including any `info`/`platformvm` methods for runtime or pin data), update both server/client Go code and the corresponding `service.md` docs.
- **Genesis & pin requirements**:
  - Genesis and network bootstrap config is under `genesis/` (for example, `genesis_mainnet.go/json`, `genesis_mustang.go/json`).
  - `genesis/genesis_pins.json` is the single source of initial IPFS pin requirements; its schema is `{"requiredDirs":[{"cid":"...","fromEpoch":0,"toEpoch":0},...]}`.
  - Any platformvm RPC (such as a `getPinRequirements`-style call) should read from this JSON (or its in-memory representation) and use the same active-epoch logic as Cryftee.
- **Runtime info surface area**:
  - A `runtimeinfo`-style type in `cryftgo` should mirror Cryftee’s `RuntimeInfo` JSON and be used by a `RuntimeInfoClient` that calls Cryftee’s `/runtime/self` endpoint.
  - Info API handlers should call into the node’s `GetRuntimeInfo` method and expose a view tailored for clients (for example, health/epoch/pin counts), handling the disabled/unreachable sidecar case gracefully.

## How to Work Effectively as an AI Agent
- Reuse existing helpers (`test_*`, `mock_*`, `New*` constructors) instead of duplicating logic.
- When changing core areas (consensus, database, APIs), search for existing usages/tests (for example, under `tests/fixture/tmpnet` and `tests/e2e`) and mirror established patterns.
- Keep changes minimal and localized; avoid broad refactors unless explicitly requested.
- After updating public interfaces, configs, or APIs, update nearby consumers and any obvious tests in the same package.
- Never reintroduce in-process runtime/middleware layers for pinning; keep all runtime health logic in the external `cryftee` sidecar and interact with it via small HTTP clients inside `cryftgo`.
