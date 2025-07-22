# ArS3nal

[![Status](https://img.shields.io/badge/status-early_development-orange)](https://github.com/your-org/ars3nal)
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

## ⚠️ Project Status: Early Development

This project is in its early stages and under active, heavy development. **It is not yet suitable for production use or,
frankly, any use.**

Check back frequently to follow the project progress. 

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgements

This project has been made possible by the [AR.IO grants program](https://ar.io/grants). 