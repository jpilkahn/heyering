# `heyering-cli`

CLI application to ingest malicious activity records from CSV file and call processor API

## Running the CLI app

After building (see workspace root README), the built `heyering-cli` binary will be available in the top-level `target/debug/` directory. Alternatively, you can run it directly with `cargo` from here:

```sh
# display `--help`  output
cargo run

# or directly ingest a CSV file
cargo run -- --path /path/to/file.csv
```

### Note on external requirements

Note that the CLI app expects the API server (see `heyering-processor-api`) to be running on `http://localhost:5000`.
