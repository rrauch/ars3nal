# ArS3nal

[![Status](https://img.shields.io/badge/latest_release-0.4.2-green)](https://github.com/rrauch/ars3nal)
[![License](https://img.shields.io/badge/License-Apache_2.0_and_MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)

ArS3nal (pronounced *arsenal*) is an S3-compatible gateway for the [AR.IO network](https://ar.io), distributed as a
single binary. It allows existing S3-native applications and tools to use the permaweb for storage simply by changing
the endpoint configuration. No code modifications are required.

The core idea is to map virtual S3 buckets to ArFS, creating what we call **Permabuckets**.

## How It Works

S3 clients expect low-latency writes, which conflicts with the asynchronous nature of permaweb finality. ArS3nal is
designed to bridge this gap with a local-first architecture:

1. **Instant Writes:** Data is written to a local Write-Ahead Log (WAL) first, providing immediate write confirmations
   and read-after-write consistency.
2. **Transparent Sync:** The gateway automatically handles bundling, signing, and uploading data to the permaweb in the
   background. Your application doesn't need to be aware of these steps.
3. **Local Caching:** Frequently accessed objects are cached locally to provide fast reads for hot data and reduce
   load on the network.

## Project Status

ArS3nal has seen its **fourth release** at this point and **is fully functional** and can be used productively.

### Main Features

From a user's point of view, ArS3nal allows both *read-only* and *read-write* access to any ArFS file system
(*public* or *private*) via the well-established S3 protocol.
Multiple Permabuckets can be made available on the same instance, each with its own friendly, configurable
path.

- [x] Configuring and listing multiple buckets
- [x] Listing, filtering, and traversing their content
- [x] Reading files/objects, including support for range requests
- [x] Support for common metadata elements, such as *last-modified*, *content-type*, and *ETag*
- [x] `if-modified-since` and `if-none-match` support for optimal client-side caching
- [x] Automatic and periodic background syncing of Permabucket content
- [x] Configurable local caching of metadata as well as actual chunk data
- [x] Automatic, proactive caching of files/objects in the background
- [x] Full cryptographic authentication of all data returned to user
- [x] Support for multiple, configurable gateways and automatic route optimization
- [x] Ready-to-use Docker image available
- [x] `systemd` integration (Linux only)
- [x] Instant write support
- [x] On-demand rollback of uncommitted changes
- [x] S3-compatible access control
- [x] Encryption support for *private* ArFS file systems
- [x] Automatic uploading of changed data in the background
- [x] Bundling of multiple modifications into single, efficient upload
- [x] Cost control
- [x] *Turbo* and direct upload support
- [x] *Dry-run* mode (for development/testing)

## Technical Details

ArS3nal is written entirely in Rust and includes comprehensive implementations of core Arweave-related
concepts and components. The core goals behind this new stack are **correctness**, **robustness**, and
**efficiency**.

Throughout the codebase, great care was taken to eliminate whole classes of bugs and issues and to ensure resource
consumption remains low—all while being compatible with the existing ecosystem.

This project has produced multiple crates that build upon each other and represent different levels of abstraction:

- [ario-core](ario-core): Core, lower-level types and functions; mostly around Transactions, Bundles, Signatures,
  Chunks, Merkle Trees, etc.
- [ario-client](ario-client): Mid-level library for interacting with gateways and their APIs, reading and writing data,
  as well as caching of said data.
- [foyer-cache](foyer-cache): L2 metadata and chunk cache for use with [ario-client](ario-client); built upon the
  popular [foyer](https://foyer-rs.github.io/foyer/) caching library.
- [arfs](arfs): ArFS implementation built upon [ario-client](ario-client). Uses SQLite internally to keep a
  persistent, local state.
- [ars3nal](ars3nal): Actual S3 gateway implementation, built upon [arfs](arfs) as well as
  [axum](https://github.com/tokio-rs/axum), the popular,
  high-performance Rust web framework, and [S3S](https://github.com/s3s-project/s3s), an established and well-tested
  framework for building S3-compatible services.

One of ArS3nal's goals is to release these crates separately so they can be used independently of ArS3nal to build
idiomatic, robust, and performant services and tools in Rust for the [AR.IO network](https://ar.io) and the wider
Arweave
ecosystem.

## Getting Started

### Using Docker

#### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/rrauch/ars3nal:latest
```

#### Run

```bash
# Create a persistent volume `ars3nal_data`
docker volume create ars3nal_data
```

The Docker image expects a config file named `ars3nal.toml` in the root of this volume.
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

(See https://rustup.rs/ for more options.)

A C compiler may be required for the embedded SQLite database engine. This will depend on the platform.

#### Checkout Source via Git

```bash
git clone https://github.com/rrauch/ars3nal.git
```

#### Build the ars3nal Binary

```bash
cd ars3nal/ars3nal
cargo build --release
```

*(Good time for a coffee break.)*

#### Quick Check

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
follow platform standards but can be easily overridden.

### config.toml

Below is a full config file as an example. All sections and values are optional. ArS3nal comes with reasonable defaults
out of the box.

```toml
[general]
# Stores SQLite databases containing ArFS state
data_dir = "/path/to/persistent/state"
temp_dir = "/path/for/temp/data" # defaults to platform standard

# Host and port to listen on
[server]
host = "localhost"
port = 6767

# Automatic gateway checking and route optimization
[routemaster]
# Monitors state of network devices; recalculates routing optimizations if network change detected
netwatch_enabled = true
# List of one or more gateway endpoints to use. Uses 'https://arweave.net' by default.
gateways = ["https://arweave.net"]
# Expected Network ID. Accepts 'main' | 'mainnet', 'test' | 'testnet', or any custom identifier
network = "mainnet"

# Turbo settings
[turbo]
# Custom Upload API endpoint URL
upload_endpoint = "https://upload.ardrive.io/"
# Custom Payment API endpoint URL
payment_endpoint = "https://payment.ardrive.io/v1/"

# ArS3nal uses two caching layers: L1 is a transient in-memory cache,
# while L2 is a persistent on-disk cache. L2 can be disabled if required.
# Metadata and chunk caching limits are configured separately.
[caching]
metadata_l1_cache_size = "8MiB"
metadata_l2_cache_dir = "/path/to/l2/metadata"
metadata_l2_cache_size = "256MiB"
chunk_l1_cache_size = "16MiB"
chunk_l2_cache_dir = "/path/to/l2/chunk"
chunk_l2_cache_size = "4GiB"
l2_enabled = true
proactive_caching_enabled = true
proactive_caching_interval_days = 60

# Automatic background sync settings
[syncing]
# Resync every n seconds
interval_secs = 900
# Initial cool-off period after starting ArS3nal
min_initial_wait_secs = 30
# No more than n buckets will be synced concurrently at any given time.
# Setting this too high can easily lead to being rate-limited by the gateway.
max_concurrent_syncs = 1

# Instance-wide upload settings
[uploading]
# ArS3nal automatically batches modifications into bundles and uploads them
# after a certain amount of time without any new changes.
batch_settle_time_secs = 300
# No more than n uploads will be performed concurrently at any given time.
# Similar to `max_concurrent_syncs` above.
max_concurrent_uploads = 1

# Permabuckets are configured below. Use one `[[permabucket]]` per ArFS drive.

[[permabucket]]
# Bucket will be reachable at http://localhost:6767/bucket1/
name = "bucket1"
drive_id = "<<drive-uuid>>"
# Can be either 'ro' (read-only, default) or 'rw' (read-write)
access_mode = "ro"
# Only for read-only public drives
owner = "<<owner address>>"
# Required for private drives or when in read-write mode
wallet = "<<name of configured wallet>>" # e.g., "wallet1"
# Only required for private drives
drive_password = "<<drive password>>"
# Refers to a specific bucket policy.
# Defaults to a public, read-only policy if not specified.
policy = "<<name of policy to apply>>" # e.g., "public-read-only"
# Required when in read-write mode
uploader = "<<name of configured uploader to use>>" # e.g., "uploader1"

# Users can be configured here. Use one `[[user]]` section per user.

[[user]]
access_key = "12345"
secret_key = "67890"
principal = "arn:aws:iam::123456789012:user/john-doe"

# IAM-like S3 bucket policies can be specified. Can be set multiple times.
# Each policy requires a unique name. Policies can be either inline
# via the `json` attribute or can refer to an external file via the `file` attribute instead.

[[policy]]
# Internal name/alias
name = "public-read-only"
json = '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBasicReading",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetObjectAttributes"
      ],
      "Resource": "*"
    }
  ]
}
'''
# file = "/path/to/policy/json_file"

# Wallets/private keys for signing and access to private drives

[[wallet]]
# Internal name/alias
name = "wallet1"
jwk = "/path/to/jwk-file"

# Multiple uploaders can be configured below

[[uploader]]
name = "uploader1"
mode = "direct" # either "direct" or "turbo"
wallet = "<<name of upload signing wallet>>" # e.g., "wallet1"
price_adjustment = "<<adjust reward by a certain percentage; see below>>" # "direct" mode only, optional
price_limit = "<<max acceptable price; see details below>>" # optional cost control price limit
min_confirmations = 3 # minimum number of confirmations needed before upload is considered accepted 
dry_run = false # disables actual data upload; mainly for testing/development
```

## Access Control

### Policy

ArS3nal supports S3-style bucket policies. One or more policies can be set in the config file, each in their
own `[[policy]]` section. The actual IAM policy in JSON form can be either inlined directly or kept in an external
file.

Use the `policy` attribute in the `[[permabucket]]` section to map a policy to a bucket.

**Warning:** If no policies are configured, ArS3nal uses a built-in default that allows basic reading for anyone (similar
to the example policy in the configuration section above). If this is not the desired behavior, make sure to set a more
restrictive policy for your Permabuckets.

ArS3nal follows the same approach AWS uses when evaluating policy rules:

**[explicit deny] > [explicit allow] > [implicit deny]**

Limitations:

* Only `s3:` actions are supported
* Only `AWS` and `*` principal types are supported (service types are not)
* Omitting the principal is treated as a wildcard
* `Conditions` are not supported

### Users

Users are configured using `[[user]]` sections in the config file. The `access_key` and `secret_key` fields authenticate
signed requests. The `principal` field can be set to any arbitrary value (ARN format is not enforced) and is matched
against policy rules during authorization.

## Wallets and Private Drives

ArS3nal supports both public and private drives in read-only and read-write modes. Depending on the configuration,
different elements are required.

### Wallets

Wallets (private keys) can be configured instance-wide and then activated on a per-bucket basis. Each wallet requires
only a name and a path to a valid JWK file containing the private key.

When accessing a public drive in read-only mode, you can configure access by setting either a wallet or just the owner
address. Private drives *always* require the correct wallet and drive password, even in read-only mode.

### Requirements Matrix

The following table shows what information is required for each access scenario:

|                   |       **Read-Only**       |      **Read-Write**       |
|:------------------|:-------------------------:|:-------------------------:|
| **Public Drive**  |      Owner or Wallet      |          Wallet           |
| **Private Drive** | Wallet and Drive Password | Wallet and Drive Password |

## Uploads

ArS3nal follows a local-first approach with eventual consistency. Hence, all changes are first applied locally and
recorded in the Write-Ahead Log.

After a certain amount of time of inactivity, all currently uncommitted changes are
bundled together and uploaded automatically.

Uploads are considered *finalized* when they can be found on the blockweave.

### Syncing and Diverging

All buckets start out in a fully synced *permanent state*, meaning they are in sync with their current permanent state
(as of the last sync).

Once local changes are made, a bucket *diverges* from that state and enters *WAL state*.
While a bucket is in this WAL state, it will **not** sync again until:

- All changes have been uploaded and finalized, or
- The current changes are discarded and the state is rolled back to the most recent permanent state.

Once either of the above conditions is met, automatic background syncing will be activated again.

Please note that it *is* still possible to make further changes while a bucket is in WAL state waiting for
finalization of a previous changeset. The newer changes simply become part of the next batch, uploaded once the current
batch is considered finalized and `batch_settle_time_secs` is met.

### Upload Modes

ArS3nal supports two different upload modes:

#### Direct

In Direct mode, ArS3nal uploads the changeset bundle as a signed transaction
directly to a gateway (as configured in the `[routemaster]` section). The associated wallet needs to have sufficient
funds for the upload to proceed.

Rewards (price paid) are automatically calculated. Use the `price_adjustment` setting to influence the reward
calculation:

For example:

```toml
price_adjustment = "+5%" # overpay by 5% to ensure quick inclusion
```

`+n%` and `-n%` are supported.

#### Turbo

When set to Turbo mode, ArS3nal uploads the changeset as a signed data item to the
configured Turbo service. The price is determined by the Turbo service provider, and a sufficient
balance needs to be maintained with the provider for the given signing wallet.

The `[turbo]` section allows setting custom endpoint URLs for the Turbo service API.

### Cost Control

To keep upload costs under control, ArS3nal comes with a helpful `price_limit` feature.
When configured, it ensures uploads do not proceed if the current price exceeds a certain threshold.

Here is an example:

```toml
price_limit = "25 USD/GiB"
```

`GiB` here means *gibibyte*, as in 2^30 bytes. `GB` is also allowed and would mean *gigabyte* (10^9 bytes).
ArS3nal supports all typical byte size units: `B`, `KiB`, `KB`, `MiB`, `MB`, `GiB`, `GB`, `TiB`, `TB`, `PiB`, `PB`.

#### Supported Currencies

The following native cryptocurrencies are supported: `AR`, `W`.

Several other currencies are also supported. However, they depend on a known exchange rate. ArS3nal uses the publicly
available CoinGecko API to get up-to-date exchange rates for the following currencies:

`USD`, `EUR`, `CNY`, `JPY`, `GBP`

Exchange rates are updated roughly every 5 minutes. The retrieved exchange rates are assumed to be correct; no further
validation is performed.

*Please note*: Under no circumstances does ArS3nal guarantee that costs stay within the configured limits. Use ArS3nal
at your own risk.

## Logging

ArS3nal uses Rust's `tracing` framework for logging. The default log level is `INFO`.
This can be changed via the `RUST_LOG` environment variable.

Known log levels are: `Error`, `Warn`, `Info`, `Debug`, and `Trace`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgements

This project has been made possible by the [AR.IO grants program](https://ar.io/grants).