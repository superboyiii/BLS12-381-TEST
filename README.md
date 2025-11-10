# BLS12-381 MultiExp Test Suite for Neo

Automated testing framework for BLS12-381 MultiExp operations on Neo blockchain.

## Overview

This repository provides comprehensive testing tools for BLS12-381 MultiExp cryptographic operations, supporting both G1 and G2 curve testing with compressed and Ethereum formats.

## Features

- **Automated Testing**: End-to-end test automation with result verification
- **Multi-Format Support**: Compressed format and Ethereum format testing
- **Dual Curve Testing**: Support for both G1 and G2 curves
- **Test Data Generation**: Go-based test data generator (`pairing_gen.go`)
- **Neo VM Integration**: C# helper for generating and executing Neo VM scripts
- **RPC Verification**: RPC-based result verification against Neo nodes

## Quick Start

```bash
# Run G1 curve test (default)
./test_bls12381_multiexp_enhanced.sh g1

# Run G2 curve test
./test_bls12381_multiexp_enhanced.sh g2

# Run Ethereum format tests
./test_bls12381_multiexp_enhanced.sh ethereum-g1
./test_bls12381_multiexp_enhanced.sh ethereum-g2
```

## Project Structure

```
├── test_bls12381_multiexp_enhanced.sh    # Main automated test script
├── Bls12381MultiExpHelper/                # C# helper for Neo VM script generation
│   └── Bls12381MultiExpHelper.cs
├── evm/                                   # Go test data generator
│   └── pairing_gen.go
└── neo/                                   # Neo blockchain source code
```

## Prerequisites

- Go (for test data generation)
- .NET SDK 9.0 (for C# helper compilation)
- curl (for RPC calls)
- jq or Python (for JSON parsing)
- Running Neo node with RPC access

## Documentation

- [Test Script Documentation](test_bls12381_multiexp_enhanced.md) - Detailed usage guide
- [Bls12381MultiExpHelper Guide](Bls12381MultiExpHelper/Bls12381MultiExpHelper.md) - C# helper documentation

## License

See [LICENSE](LICENSE) file for details.
