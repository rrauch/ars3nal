# ArS3nal

[![Status](https://img.shields.io/badge/status-first_release-yellow)](https://github.com/rrauch/ars3nal)
[![License](https://img.shields.io/badge/License-Apache_2.0_and_MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)

ArS3nal (pronounced *arsenal*) is an S3-compatible gateway for the [AR.IO network](https://ar.io), distributed as a
single binary. It allows existing S3-native applications and tools to use the permaweb for storage simply by changing
the endpoint configuration. No code modifications are required.

The core idea is to map virtual S3 buckets to ArFS, creating what we call **Permabuckets**.

## How It Works

S3 clients expect low-latency writes, which conflicts with the asynchronous nature of permaweb finality. ArS3nal is
designed to solve this "impedance mismatch" with a local-first architecture:

1. **Instant Writes:** Data is written to a local Write-Ahead-Log (WAL) first, providing immediate write confirmations
   and read-after-write consistency.
2. **Transparent Sync:** The gateway automatically handles bundling, signing, and uploading data to the permaweb in the
   background. Your application doesn't need to be aware of these steps.
3. **Local Caching:** Frequently accessed objects are cached locally to provide fast reads for hot data and reduce
   load on the network.

## Project Status: First working release

After an intense initial development phase, we are happy to announce the first working release of ArS3nal! Although
it's still early days, ArS3nal **is ready** to be tried out and tested - albeit still in a limited fashion.

Check back frequently to follow the project progress.

### What works?

From a user's point of view, ArS3nal allows *read-only* access to any *public* ArFs file system via the well-established
S3 protocol.
Multiple **Permabuckets** can be made available on the same instance, each getting their own friendly, configurable
path.

- [x] Configuring & listing multiple buckets
- [x] Listing, filtering & traversing their content
- [x] Reading files / objects, including support for range requests
- [x] Support for common metadata elements, such as *last-modified*, *content-type*, and *ETag*
- [x] `if-modified-since` & `if-none-match` support for optimal client-side caching
- [x] Automatic and periodic background syncing of **Permabucket** content
- [x] Configurable local caching of metadata as well as actual chunk data
- [x] Full **cryptographic authentication** of all data returned to user
- [x] Support for multiple, configurable Gateways and automatic route optimization
- [x] Ready-to-use Docker image available
- [x] `systemd` integration (Linux only)
- [ ] Instant Write support
- [ ] Automatic uploading of changed data in the background
- [ ] Encryption support for *private* ArFs file systems.
- [ ] S3 compatible access control

## Technical Details

ArS3nal is written entirely in Rust and includes comprehensive implementations of core Arweave
related concepts and components. The core ideals behind this new stack are **correctness**, **robustness** &
**efficiency**.

Throughout the codebase a lot of care was taken to eliminate whole classes of bugs and issues and to ensure resource
consumption remains low - all while being compatible with the existing ecosystem. Latency is kept to a minimum at all
times.

This project has produced multiple `crates` that build upon each other and represent different levels of abstractions:

- [ario-core](ario-core): core, lower-level types and functions; mostly around Transactions, Bundles, Signatures,
  Chunks, Merkle-Trees, ...
- [ario-client](ario-client): mid-level library; for interacting with gateways and their APIs, reading and writing data
  as well as caching of said data.
- [foyer-cache](foyer-cache): L2 metadata and chunk Cache, for use with [ario-client](ario-client); built upon the
  popular [foyer](https://foyer-rs.github.io/foyer/) caching library.
- [arfs](arfs): ArFs implementation; built upon [ario-client](ario-client). Uses `SQLite` internally to keep a
  persistent, local state.
- [ars3nal](ars3nal): Actual S3 gateway implementation, built upon [arfs](arfs) as well as
  on [axum](https://github.com/tokio-rs/axum) the popular,
  high performance Rust web framework and [S3S](https://github.com/s3s-project/s3s), an established and well-tested
  framework to build S3 compatible services.

One of ArS3nals goals is to release these crates separately, so they can be used independently of ArS3nal to build
idiomatic, robust and performant services and tools in Rust for the [AR.IO network](https://ar.io) and the wider Arweave
ecosystem.

## Getting Started

### Using Docker

#### Pull from Github Container Registry

```bash
docker pull ghcr.io/rrauch/ars3nal:latest
```

#### Run

```bash
# Create a persistent volume `ars3nal_data`
docker volume create ars3nal_data
```

The docker image expects a config file named `ars3nal.toml` in the root of this volume.
See below for details.

```bash
# Run the Docker container in the foreground
docker run -it --rm -p 6767:6767 -v ars3nal_data:/ars3nal ghcr.io/rrauch/ars3nal
```

ArS3nal is now accessible at http://localhost:6767. That's it!

### Building from Source

#### Prerequisites

A recent Rust compiler and stable toolchain is required to build ArS3nal from source:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

(see https://rustup.rs/ for more options)

A C compiler *may* be required for the embedded SQLite database engine. This will depend on the platform.

#### Checkout Source via Git

```bash
git clone https://github.com/rrauch/ars3nal.git
```

#### Build the ars3nal binary

```bash
cd ars3nal/ars3nal
cargo build --release
```

*(good time for a coffee break)*

#### Quick check

```bash
 ../target/release/ars3nal --help
```

This should show the help page below.

## Configuration

ArS3nal is mainly configured through its config file. Furthermore, command-line arguments as well as environment
variables can be used to override certain default values:

```
user@localhost:~/$ /usr/local/bin/ars3nal --help
Exports one or more ArDrives via S3.

If no commands are specified, the server process will run and export permabuckets as configured.

Usage: ars3nal [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to Config File
          
          [env: CONFIG=]
          [default: /home/user/.config/ars3nal/config.toml]

  -d, --data <DATA>
          Path to Default Data directory. Can be overridden for each permabucket in the Config File
          
          [env: DATA=]
          [default: /home/user/.local/share/ars3nal]

  -m, --metadata-cache <METADATA_CACHE>
          Path to Metadata L2 Cache directory. Can be overridden in the Config File
          
          [env: METADATA_CACHE=]
          [default: /home/user/.cache/ars3nal/metadata]

  -k, --chunk-cache <CHUNK_CACHE>
          Path to Chunk L2 Cache directory. Can be overridden in the Config File
          
          [env: CHUNK_CACHE=]
          [default: /home/user/.cache/ars3nal/chunk]

  -l, --host <HOST>
          Default Host to listen on
          
          [env: HOST=]
          [default: localhost]

  -p, --port <PORT>
          Default Port to listen on
          
          [env: PORT=]
          [default: 6767]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

By default, ArS3nal will listen on http://localhost:6767/. The default location of the config file will
follow platform standards, but can be easily overridden.

### config.toml

Below is a full config file as an example. All sections and values are optional. ArS3nal comes with reasonable defaults
out-of-the-box.

```toml
[general]
# Stores SQLite databases containing ArFS state
data_dir = "/path/to/persistent/state"

# Host & Port to listen on
[server]
host = "localhost"
port = 6767

# Automatic Gateway checking and route optimization
[routemaster]
# Monitors state of network devices; recalculates routing optimizations if network change detected
netwatch_enabled = true
# List of one or more gateway endpoints to use. Uses 'https://arweave.net' by default.
gateways = ["https://arweave.net"]
# Expected Network ID. Accepts 'main' | 'mainnet' , 'test' | 'testnet' or any custom identifier
network = "mainnet"

# ArS3nal uses two caching layers, L1 is a transient in-memory cache
# while L2 is a persistent on-disk cache. L2 can be disabled if required.
# Metadata and Chunk Caching limits are configured separately
[caching]
metadata_l1_cache_size = "8MiB"
metadata_l2_cache_dir = "/path/to/l2/metadata"
metadata_l2_cache_size = "256MiB"
chunk_l1_cache_size = "16MiB"
chunk_l2_cache_dir = "/path/to/l2/chunk"
chunk_l2_cache_size = "4GiB"
l2_enabled = true

# Automatic background sync settings
[syncing]
# Resync every n seconds
interval_secs = 900
# Initial cool-off period after starting ArS3nal
min_initial_wait_secs = 30
# No more than n buckets will be synced concurrently at any given time.
# Setting this too high can easily lead to being rate-limited by the Gateway
max_concurrent_syncs = 1

# Permabuckets are configured below. Use one `[[permabucket]]` per ArFs drive. 

[[permabucket]]
# Bucket will be reachable at http://localhost:6767/bucket1/
name = "bucket1"
drive_id = "<<drive-uuid>>"
owner = "<<owner address>>"
```

## Logging

ArS3nal uses Rust's `tracing` framework for logging. The default log-level is `INFO`.
This can be changed via the `RUST_LOG` environment variable.

Known log levels are: `Error`, `Warn`, `Info`, `Debug`, & `Trace`

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgements

This project has been made possible by the [AR.IO grants program](https://ar.io/grants).