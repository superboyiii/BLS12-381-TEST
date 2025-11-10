# BLS12-381 MultiExp Enhanced Test Script

Automated test script for BLS12-381 MultiExp operations on Neo blockchain, supporting both G1 and G2 curve testing with compressed and Ethereum formats.

## Features

- Support G1 and G2 curve testing
- Support Ethereum format testing (using Ethereum test vectors)
- Support compressed format testing (using generated test data)
- Automatic test data generation via `pairing_gen.go`
- Neo VM script generation and execution
- RPC-based result verification
- Multiple test runs with statistics

## Prerequisites

- **Go** - Required to run `pairing_gen.go`
- **.NET SDK** - Required to compile and run `Bls12381MultiExpHelper.cs`
- **curl** - Required for Neo RPC calls
- **jq** or **Python** - Required for JSON parsing (jq preferred)
- **Neo node** - Must be running and accessible via RPC

## Usage

```bash
./test_bls12381_multiexp_enhanced.sh [test_type] [num_tests] [max_scalars]
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `test_type` | string | `g1` | Test type to execute. Valid values: `g1`, `g2`, `ethereum-g1`, `ethereum-g2` |
| `num_tests` | integer | `1` | Number of test iterations to run |
| `max_scalars` | integer | `128` | Maximum number of scalars per test (only used for `g1` and `g2` modes) |

### Test Types

- **`g1`** - Test G1 curve with compressed format. Generates random test data using `pairing_gen.go`.
- **`g2`** - Test G2 curve with compressed format. Generates random test data using `pairing_gen.go`.
- **`ethereum-g1`** - Test G1 curve with Ethereum format. Uses predefined Ethereum test vectors from Neo's test suite.
- **`ethereum-g2`** - Test G2 curve with Ethereum format. Uses predefined Ethereum test vectors from Neo's test suite.

**Note:** For Ethereum format tests, `max_scalars` parameter is ignored as they use fixed test vectors.

## Examples

### Basic Usage

```bash
# Run a single G1 test with default settings
./test_bls12381_multiexp_enhanced.sh

# Run 10 G1 tests with maximum 5 scalars each
./test_bls12381_multiexp_enhanced.sh g1 10 5

# Run 5 G2 tests with default max_scalars (128)
./test_bls12381_multiexp_enhanced.sh g2 5

# Run Ethereum G1 test vectors
./test_bls12381_multiexp_enhanced.sh ethereum-g1

# Run Ethereum G2 test vectors
./test_bls12381_multiexp_enhanced.sh ethereum-g2
```

### Advanced Usage

```bash
# Run multiple G1 tests with small scalar count for faster execution
./test_bls12381_multiexp_enhanced.sh g1 20 3

# Run comprehensive G2 tests with large scalar count
./test_bls12381_multiexp_enhanced.sh g2 1 256
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | `http://localhost:20332` | Neo RPC endpoint URL |

### Example

```bash
# Use custom RPC endpoint
export RPC_URL="http://192.168.1.100:20332"
./test_bls12381_multiexp_enhanced.sh g1 5
```

## How It Works

1. **Test Data Generation** - For `g1`/`g2` modes, calls `pairing_gen.go` to generate random test data. For Ethereum modes, uses predefined test vectors.

2. **C# Helper Update** - Updates `Bls12381MultiExpHelper.cs` with generated test parameters (points and scalars).

3. **Neo VM Script Generation** - Compiles and runs the C# helper to generate a Neo VM script.

4. **RPC Execution** - Calls Neo RPC `invokescript` method to execute the generated script.

5. **Result Comparison** - Compares the RPC result with the expected result from `pairing_gen.go`.

6. **Statistics** - Displays test results including pass/fail counts and saves failed test details to a log file.

## Output

The script provides colored output indicating:

- **Green (✓)** - Test passed
- **Red (✗)** - Test failed
- **Yellow** - Warnings and notes
- **Cyan** - Section headers and information

### Output Files

- **Failed Test Log** - Saved to `failed_tests_YYYYMMDD_HHMMSS.log` in the scripts directory, containing detailed parameters of failed tests.

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed or script error occurred

## Troubleshooting

### Common Issues

1. **RPC Connection Failed**
   - Ensure Neo node is running
   - Check `RPC_URL` environment variable
   - Verify network connectivity

2. **Missing Dependencies**
   - Install required tools (go, dotnet, curl, jq/python)
   - Ensure tools are in PATH

3. **File Not Found**
   - Ensure `pairing_gen.go` exists in `scripts/evm/`
   - Ensure `Bls12381MultiExpHelper.cs` exists in `scripts/`

4. **Permission Denied**
   - Make script executable: `chmod +x test_bls12381_multiexp_enhanced.sh`

## Notes

- The script automatically restores `Bls12381MultiExpHelper.cs` to its original state after execution.
- Temporary files are cleaned up automatically on exit.
- For Ethereum format tests, G2 testing may have format compatibility issues (see script warnings).

