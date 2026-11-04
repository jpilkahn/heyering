# `heyering-integration-test`

Crate that holds a (minimal) full-flow integration test.

This is a dummy crate without actual source code, holding only the integration test itself.

## Running the integration test

Prior to integration testing, the project must have been built (in debug mode).
If you haven't done so yet, build the project by running

```sh
cargo build
```

in the workspace root (i.e. this crates parent directory).

Run the integration test by executing

```sh
cargo test
```

inside the crate root.
