---
status: Proposed
date: 2026-11-01
deciders: Johannes Pilkahn (candidate), Eye Security Heyering team
---

# Eye Security Technical Assessment

## AD #1: Project Structure

How should the project be structured?

### Context and Problem Statement

Which concept is used to structure the project into logical components?

### Decision Drivers

* Maintainability & Testability
* DRY principle

### Considered Options

1. One crate with multiple entry points
2. `cargo` workspace with three crates (CLI application, server (processor) application with endpoint(s), library consumed by both holding shared types and logic)

### Decision Outcome

A cargo workspace with the aforementioned three crates clearly is the most extensible solution.

#### Consequences

* Good: Extensibility, Maintainability & Testability
* Bad: None

## AD #2: Chunking, rate-limiting

Which project component should handle the chunking and waiting, i.e. the adherence to the `/analytics/` endpoints rate limit?

### Context and Problem Statement

As per the provided documentation the `/analytics/` endpoint is rate-limited to 20 records per 10 seconds time. Some project component will have to handle it.

### Decision Drivers

* Adherence to the spec
* Simplicity

### Considered Options

The rate-limit could either be handled by the CLI app that ingests the CSV-based records, or by the API app that the CLI posts the records to. If the API would handle it, the CLI app would be simpler, could be kept agnostic of the underlying pitfalls and simply post all records to the processor API endpoint, which in turn would call the existing heyering APi endpoints in a background task (green thread). However, this would mean that in order to provide proper feedback to the CLI user, we would need a second endpoint to report progress of the spawned background task back to the CLI app.

### Decision Outcome

Let the CLI app handle the chunking, such that a single endpoint suffices for proper progress reporting.

#### Consequences

* Good: Simplicity
* Bad: Increased complexity on the CLI side, potentially incomplete file upload should the CLI app be terminated early

## AD #3: Observability

How to satisfy the observability requirement?

### Context and Problem Statement

As per the ticket, proper observability is a requirement. Feedback to the CLI-user could be given by simple `println!("...")` statements, this would however not be very extensible.

### Decision Drivers

* Extensibility
* (Future) integration with OpenTelemetry / jaeger / grafana or similar

### Considered Options

* printing to stdout
* Rust's `log` crate
* Rust's `tracing` crate

### Decision Outcome

The `tracing` crate will be used to log progress and/or errors.

#### Consequences

* Good: We can collect structured, event-based diagnostics, with proper context by grouping logged events in spans
* Bad: Additional external dependency
