# Wamble

Wamble is a multiplayer chess variant where after every move you're switched to a new board. The goal is to keep it fast, small, and with minimal deps.

## Features

### Host facing

- Single config file with a small Lisp inspired syntax.
- Hot reloading on POSIX without dropping sockets or cached boards is achieved by sending `SIGHUP` to reload.
- Run multiple profiles in one process. Each profile has its own port, DB creds/connection, and visibility tier; advertised profiles get their own UDP listener thread.
- PostgreSQL stores everything?
- Compact UDP based protocol with ACKs, retries, and NAT session binding.
- Board pool manager sizes itself, keeps some games in memory, and archives idle/finished boards.

### Player facing

- After every move you're switched to a new board from the shared pool.
- Matching weights game phase and experience so new players get new-ish games and veterans get middle/end game positions.
- Spectate a summary feed or lock onto one board.
- Play anonymously or for persistentcy attach a key.
- Legal move hints, UCI is validated by a bitboard engine.
- Scored by pot rewarding contributors of each board.
- [planned] skill level rating

## Getting Started

### Prerequisites

- A C compiler (like `gcc` or `clang`)
- PostgreSQL for the database

### Database Setup

1.  Install PostgreSQL

2.  Create a database and user for Wamble. ig you can do this by running:

    ```sql
    CREATE DATABASE wamble;
    CREATE USER wamble_user WITH PASSWORD 'your_password_here';
    GRANT ALL PRIVILEGES ON DATABASE wamble TO wamble_user;
    ```

3.  Apply the initial schema which is in `migrations/001_initial_schema.sql`. You can apply it using `psql`:

    ```sh
    psql -U wamble_user -d wamble -f migrations/001_initial_schema.sql
    ```

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
build/wamble_build --tests --run-tests [--with-no-db] [--warn]
```

To remove DB-backed code in tests, add `--with-db`:

```sh
build/wamble_build --tests --run-tests --with-db
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
- To temporarily skip DB-backed tests, set `WAMBLE_SKIP_DB_TESTS=1`.
- A helper tool `build/wamble_db_tool` is built when `--with-db` is used. Examples:
  - Migrate schema: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --migrate`
  - Load fixtures: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --fixture`
  - Reset tables: `WAMBLE_TEST_DSN=... build/wamble_db_tool --schema test_schema --reset`

## How to Run

Once you've built the server, you can run it with:

```sh
build/wamble
```

The server will start listening for connections on the default port (8888).

## Configuring

Lisp like configuration run server with `--help` and read docs/configuration.txt for details.
