# `heyering` technical assessment

This repository is a `cargo` workspace consisting of three crates holding source code and an additional fourth crate with a full-flow integration test:

* The `heyering-cli` crate holds a CLI application to parse malicious activity records from an input CSV file (see `data/example_data_2.csv`).
* The `heyering-processor-api` crate holds server application offering a single endpoint the CLI application can use to post the parsed records to. This application in turn calls the provided heyering API's enrichment and analytics services.
* The `heyering-lib` crate holds types and logic shared between the two aforementioned application crates.
* The `heyering-integration-test` crate holds a full-flow integration test.

## Building the project

### Prerequisites

If you haven't done so yet, install the rust programming language via the [`rustup`](https://rustup.rs/) installer. You could download it via the `curl` command provided in the rustup documentation, but your *nix distribution's package manager likely includes rustup as a package. The author recommends you'd install rustup itself via your preferred package manager and thereafter the language and tooling via running the local rustup binary.

### Building

In the workspace root (the directory this README resides in), run `cargo build` to execute a (debug) build of all four crates.

```sh
cargo build
```

## Testing the project

To execute the unit and integration test(s) contained in the workspace's individual crates, run `cargo test` from the workspace root.

```sh
cargo test
```

## Running the project

### Processor API

To spin up a local instance of the API server, hop into the `heyering-processor-api` directory and execute `cargo run`:

```sh
cd heyering-processor-api
cargo run
```

### CLI application

To execute the CLI application with the provided sample data file, hop into the `heyering-cli` directory and execute `cargo run` with the `--path` argument:

```sh
cd heyering-cli
cargo run -- --path ../data/example_data_2.csv
```

## Notes

### Filtering ingested CSV records

This codebase is extensible. Adding a CLI parameter to locally filter the records prior to uploading is fairly trivial. This feature unfortunately did however not fit the allotted timebox.

I might still add it, but if I do, please note that I would have done so outside the timebox. Alternatively, I am happy to discuss (and/or implement) the feature during the upcoming interview.

### Observability

To satisfy observability concerns, this project employs the [`tracing`](https://docs.rs/tracing/latest/tracing/) crate, modern Rust's de facto standard logging solution. As per the ADR, the reasoning behind this choice is structured, event-based logging, the option to group traces in spans for context, and the interoperability with OpenTelemetry dashboards such as Grafana, jaeger, and the like.

### Security

#### Authentication / authorization

Authentication (and/or) authorization features for the API server were explicitly out-of-scope within the assessment, but it should be mentioned that in a real-world production scenario this would of course be an essential part of an API design. The author would prefer a solution along the lines of OpenID connect.

#### Secrets

The underlying heyering API that provides the enrichment and analytics services *does* require an authorization header to be sent. Here, given time constraints and scope, the value for this header is baked into the source code as a hard-coded constant static string reference. In a real-world production scenario, this obviously had better been fetched from some sort of secrets store running in the respective deployment environment.
