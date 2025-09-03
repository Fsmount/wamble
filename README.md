# Wamble

Wamble is a multiplayer chess variant where after every move you're switched to a new board. The goal is to keep it fast, small, and with minimal deps.

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

```sh
gcc -o wamble src/*.c -Iinclude -lpq -lpthread -lm
```

This will create an executable named `wamble` in the root directory.

## How to Run

Once you've built the server, you can run it with:

```sh
./wamble
```

The server will start listening for connections on the default port (8888).

## Configuring

Lisp like configuration run server with `--help` and read docs/configuration.txt for details.
