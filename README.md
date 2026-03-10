# Wamble

Wamble is a multiplayer chess variant where after every move you're switched to a new board. The goal is to keep it fast, small, and with minimal deps.

## Features

### Host facing

- Single config file with a small Lisp inspired syntax.
- Config reload on POSIX is triggered with `SIGHUP`.
- Exec-based hot reload without dropping sockets or cached boards is triggered with `SIGUSR2`.
- Automatic PID file plus `--reload` / `--hot-reload` CLI controls for easier reload.
- Run multiple profiles in one process. Each profile has its own port, game DB connection, visibility tier, and optional profile-group selector; advertised profiles get their own UDP listener thread.
- Split PostgreSQL topology: profile DBs hold game/session state, while one shared global DB holds identities, tags, policy rules, config snapshots, and treatment configuration.
- Lisp-configured policy rules for trust tiers, profile discovery, and protocol/resource authorization.
- Profile-scoped treatment groups with defaults, predicate-based assignment, directed group edges, persistent tags, and hook-specific outputs.
- Compact UDP based protocol with ACKs, retries, and NAT session binding.
- Board pool manager sizes itself, keeps some games in memory, and archives idle/finished boards.

### Player facing

- After every move you're switched to a new board from the shared pool.
- Matching weights game phase and experience so new players get new-ish games and veterans get middle/end game positions.
- Spectate a summary feed or lock onto one board.
- Play anonymously or attach a key for persistent identity.
- Legal move hints, UCI is validated by a bitboard engine.
- Prediction mode with per-hook treatment control for gating, pending limits, scoring bonuses, and read depth.
- Scored by pot rewarding contributors of each board, with treatment-aware scoring and rating adjustments.
- Trust-aware profile discovery and visibility.
- [planned] skill level rating

## Getting Started

### Prerequisites

- A C compiler (like `gcc` or `clang`)
- PostgreSQL for the database

### Database Setup

1.  Install PostgreSQL.

2.  Create one profile database and one global database, plus a user or multiple, ig you can do this by running:

    ```sql
    CREATE DATABASE wamble_profile;
    CREATE DATABASE wamble_global;
    CREATE USER wamble_user WITH PASSWORD 'your_password_here';
    GRANT ALL PRIVILEGES ON DATABASE wamble_profile TO wamble_user;
    GRANT ALL PRIVILEGES ON DATABASE wamble_global TO wamble_user;
    ```

3.  Build the DB helper:

    ```sh
    c99 -O2 -std=c99 tools/wamble_db_tool.c -lpq -o build/wamble_db_tool
    ```

4.  Apply profile and global migrations separately:

    ```sh
    WAMBLE_TEST_DSN=postgres://user:pass@localhost:5432/wamble_profile build/wamble_db_tool --migrate-profile
    WAMBLE_TEST_DSN=postgres://user:pass@localhost:5432/wamble_global build/wamble_db_tool --migrate-global
    ```

5.  Point your config at both stores:
    `db-*` settings for the profile DB and `global-db-*` settings for the shared global DB.

### Building Wamble

Use the C build driver to build the static core library, the server, and the unified test binary.

1. Build the build driver:

```sh
c99 -O2 -std=c99 -o build/wamble_build tools/wamble_build.c
```

2. Build the server (requires libpq):

```sh
build/wamble_build --server [--warn]
```

3. Build and run the unified tests (optional):

```sh
build/wamble_build --tests --run-tests [--warn]
```

You can pass arguments to the test runner after `--`, for example:

```sh
build/wamble_build --tests --run-tests -- --module network --timeout-ms 8000 --seed 42
```

List available tests without running them:

```sh
build/wamble_build --tests --list-tests
```

Clean build artifacts:

```sh
build/wamble_build --clean
```

Artifacts are placed under `build/`

### Test Fixtures

- Set `WAMBLE_TEST_DSN` to point tests/tools at a Postgres instance, e.g. `export WAMBLE_TEST_DSN=postgres://user:pass@localhost:5432/wamble_test`.
- To temporarily skip DB-backed tests without rebuilding, set `WAMBLE_SKIP_DB_TESTS=1`.
- The helper tool `build/wamble_db_tool` is built when DB support is enabled (default). Examples:
  - Migrate a profile schema: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --migrate-profile`
  - Migrate a global schema: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --migrate-global`
  - Load fixtures: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --fixture`
  - Reset tables: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --reset`

DB-backed tests are automatically skipped if `WAMBLE_TEST_DSN` is not set.

## How to Run

Once you've built the server, you can run it with:

```sh
build/wamble
```

The server will start listening for connections on the default port (8888).

## Configuring

Lisp like configuration run server with `--help` and read docs/configuration.txt for details.
