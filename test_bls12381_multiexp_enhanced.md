# BLS12-381 MultiExp Enhanced Test Script

Automated test script for BLS12-381 MultiExp operations on Neo blockchain, supporting both G1 and G2 curve testing with compressed and Ethereum formats.

## Features

- Support G1 and G2 curve testing
- Support Ethereum format testing (using Ethereum test vectors)
- Support compressed format testing (using generated test data)
- Support BLS12-381 Add operations (G1Add, G2Add)
- Support BLS12-381 Mul operations (G1Mul, G2Mul)
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
| `test_type` | string | `g1` | Test type to execute. Valid values: `g1`, `g2`, `ethereum-g1`, `ethereum-g2`, `g1add`, `g2add`, `g1mul`, `g2mul` |
| `num_tests` | integer | `1` | Number of test iterations to run |
| `max_scalars` | integer | `128` | Maximum number of scalars per test (only used for `g1` and `g2` modes) |

### Test Types

#### MultiExp Operations

- **`g1`** - Test G1 curve MultiExp with compressed format. Generates random test data using `pairing_gen.go`.
- **`g2`** - Test G2 curve MultiExp with compressed format. Generates random test data using `pairing_gen.go`.
- **`ethereum-g1`** - Test G1 curve MultiExp with Ethereum format. Uses predefined Ethereum test vectors from Neo's test suite.
- **`ethereum-g2`** - Test G2 curve MultiExp with Ethereum format. Uses predefined Ethereum test vectors from Neo's test suite.

#### Add Operations (Ethereum Format)

- **`g1add`** - Test G1 point addition (`bls12_g1add`). Generates random G1 points and tests point addition in Ethereum format.
- **`g2add`** - Test G2 point addition (`bls12_g2add`). Generates random G2 points and tests point addition in Ethereum format.

#### Mul Operations (Ethereum Format)

- **`g1mul`** - Test G1 point multiplication (`bls12_g1mul`). Generates random G1 points and scalars, tests point-scalar multiplication in Ethereum format.
- **`g2mul`** - Test G2 point multiplication (`bls12_g2mul`). Generates random G2 points and scalars, tests point-scalar multiplication in Ethereum format.

**Note:** 
- For Ethereum format tests (`ethereum-g1`, `ethereum-g2`), `max_scalars` parameter is ignored as they use fixed test vectors.
- For Add/Mul operations (`g1add`, `g2add`, `g1mul`, `g2mul`), `max_scalars` parameter is ignored as they use single operations.

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

# Run G1 addition tests (5 iterations)
./test_bls12381_multiexp_enhanced.sh g1add 5

# Run G1 multiplication tests (5 iterations)
./test_bls12381_multiexp_enhanced.sh g1mul 5

# Run G2 addition tests (3 iterations)
./test_bls12381_multiexp_enhanced.sh g2add 3

# Run G2 multiplication tests (3 iterations)
./test_bls12381_multiexp_enhanced.sh g2mul 3
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

### MultiExp Operations (`g1`, `g2`, `ethereum-g1`, `ethereum-g2`)

1. **Test Data Generation** - For `g1`/`g2` modes, calls `pairing_gen.go` to generate random test data. For Ethereum modes, uses predefined test vectors.

2. **C# Helper Update** - Updates `Bls12381MultiExpHelper.cs` with generated test parameters (points and scalars).

3. **Neo VM Script Generation** - Compiles and runs the C# helper to generate a Neo VM script.

4. **RPC Execution** - Calls Neo RPC `invokescript` method to execute the generated script.

5. **Result Comparison** - Compares the RPC result with the expected result from `pairing_gen.go`.

6. **Statistics** - Displays test results including pass/fail counts and saves failed test details to a log file.

### Add/Mul Operations (`g1add`, `g2add`, `g1mul`, `g2mul`)

1. **Test Data Generation** - Generates random points (and scalars for Mul operations) using `pairing_gen.go`.

2. **C# Helper Update** - Updates `Bls12381MultiExpHelper.cs` with:
   - Operation type (`OPERATION_TYPE`)
   - Points (for Add: two points, for Mul: one point + scalar)
   - Scalar value (for Mul operations only)

3. **Neo VM Script Generation** - Compiles and runs the C# helper to generate a Neo VM script that calls the appropriate BLS12-381 operation (`bls12_g1add`, `bls12_g2add`, `bls12_g1mul`, or `bls12_g2mul`).

4. **RPC Execution** - Calls Neo RPC `invokescript` method to execute the generated script.

5. **Result Verification** - The script executes and returns the result. For full verification, you can manually compare with `pairing_gen.go` using the corresponding operation mode.

**Note:** Add/Mul operations use Ethereum format (uncompressed) for both input and output, which is compatible with Neo's `bls12_g1add`, `bls12_g2add`, `bls12_g1mul`, and `bls12_g2mul` methods.

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
- Add/Mul operations (`g1add`, `g2add`, `g1mul`, `g2mul`) use Ethereum format (128 bytes for G1, 256 bytes for G2) which matches Neo's implementation.
- For Add operations, the script generates two random points and tests their addition.
- For Mul operations, the script generates one random point and uses a fixed scalar (default: 2) for multiplication testing.
- You can verify Add/Mul results manually using `pairing_gen.go`:
  ```bash
  # Verify G1 addition
  go run pairing_gen.go g1add --input <256_bytes_hex>
  
  # Verify G1 multiplication
  go run pairing_gen.go g1mul --input <160_bytes_hex>
  
  # Verify G2 addition
  go run pairing_gen.go g2add --input <512_bytes_hex>
  
  # Verify G2 multiplication
  go run pairing_gen.go g2mul --input <288_bytes_hex>
  ```

