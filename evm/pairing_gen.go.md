# pairing_gen.go

BLS12-381 test data generator for MultiExp operations. Generates random test data or processes manual/Ethereum format inputs, producing C# code snippets and expected results for Neo blockchain testing.

## Features

- Generate random G1/G2 points and scalars for testing
- Support compressed format (manual mode)
- Support Ethereum format (uncompressed, for Neo test vectors)
- Output C# code snippets ready for use in `Bls12381MultiExpHelper.cs`
- Calculate expected MultiExp results

## Prerequisites

- **Go 1.16+** - Required to run the program
- **gnark-crypto** - BLS12-381 cryptographic library (automatically fetched via `go mod`)

## Usage

The program supports three modes: **random** (default), **manual**, and **ethereum**.

### Random Mode (Default)

Generates random test data with specified maximum number of scalars.

```bash
# Default: 128 scalars, G1
go run pairing_gen.go

# Specify max_scalars
go run pairing_gen.go [max_scalars]

# Explicit random mode with max_scalars
go run pairing_gen.go random [max_scalars]

# Use G2 instead of G1
go run pairing_gen.go --use-g2
go run pairing_gen.go random --use-g2 [max_scalars]
```

**Parameters:**
- `max_scalars` (optional, default: 128) - Maximum number of scalars to generate (must be ≥ 1)
- `--use-g2` (optional) - Use G2 curve instead of G1 (default: false)

**Output:**
- Random G1/G2 point(s) in compressed format
- Random scalar values
- C# code snippets for `Bls12381MultiExpHelper.cs`
- Expected MultiExp result

### Manual Mode

Use pre-defined compressed format points and scalars.

```bash
# G1 mode
go run pairing_gen.go manual --g1 <hex> --scalars "<scalar1,scalar2,...>"

# G2 mode
go run pairing_gen.go manual --g2 <hex> --scalars "<scalar1,scalar2,...>" --use-g2
```

**Parameters:**
- `--g1` - Compressed G1 point (96 hex characters, 48 bytes)
- `--g2` - Compressed G2 point (192 hex characters, 96 bytes)
- `--scalars` - Comma-separated list of scalar values (must be wrapped in quotes)
- `--use-g2` - Use G2 point (default: false, uses G1)

**Note:** Always wrap `--scalars` value in quotes to prevent shell interpretation.

**Output:**
- C# code snippets with provided points and scalars
- Expected MultiExp result

### Ethereum Mode

Process Ethereum format (uncompressed) input for Neo test vectors.

```bash
# G1 mode
go run pairing_gen.go ethereum --input <hex>

# G2 mode
go run pairing_gen.go ethereum --input <hex> --use-g2
```

**Parameters:**
- `--input` - Ethereum format input hex string (required)
  - **G1 format:** 160 bytes per pair = 128 bytes point + 32 bytes scalar
  - **G2 format:** 288 bytes per pair = 256 bytes point + 32 bytes scalar
- `--use-g2` - Use G2 format (default: false, uses G1)

**Output:**
- Compressed MultiExp result
- Input validation information

## Examples

### Random Mode

```bash
# Generate 5 random G1 point-scalar pairs
go run pairing_gen.go 5

# Generate 10 random G2 point-scalar pairs
go run pairing_gen.go random 10 --use-g2

# Generate default (128) G2 pairs
go run pairing_gen.go --use-g2
```

### Manual Mode

```bash
# G1 with specific point and scalars
go run pairing_gen.go manual \
  --g1 b2deb4e364cc09aceb924ebe236d28b5d180e27ee0428697f3d088b7c83637820c3c0c95b83189a6301dbaa405792564 \
  --scalars "1732363698,436226955,507793302,1540421097"

# G2 with specific point and scalars
go run pairing_gen.go manual \
  --g2 a4eaf10f48781d663bf03d046d50c902088b97cd35ccbdd3fffbc2ee5cd95dc00c8894dbc84a3390cd95dcbf50ef9ece176b5efc0cba714ae43df47dd9d408daa5852cd6b47ccc2e504c7ad3e0829196d1e5a4d381edf08f8067a88c25dda003 \
  --scalars "1,2,3" \
  --use-g2
```

**PowerShell Note:** Use single quotes or escape quotes:
```powershell
go run pairing_gen.go manual --g1 <hex> --scalars '1,2,3'
# or
go run pairing_gen.go manual --g1 <hex> --scalars \"1,2,3\"
```

### Ethereum Mode

```bash
# G1 Ethereum format (from Neo test vectors)
go run pairing_gen.go ethereum \
  --input 0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000011

# G2 Ethereum format
go run pairing_gen.go ethereum \
  --input <G2_Ethereum_Format_Hex> \
  --use-g2
```

## Output Format

The program outputs:

1. **Point Information**
   - Compressed point(s) in hex format
   - C# array format for multiple points

2. **Scalar Information**
   - Scalar values array
   - C# array format

3. **Expected Result**
   - MultiExp result in compressed format
   - Hex string ready for comparison

4. **C# Code Snippets**
   - Ready-to-use code for `Bls12381MultiExpHelper.cs`
   - Includes `G1_POINTS`/`G2_POINTS` arrays or single point
   - Includes `SCALARS` array
   - Includes `USE_G2` flag

## Format Specifications

### Compressed Format

- **G1:** 48 bytes (96 hex characters)
- **G2:** 96 bytes (192 hex characters)

### Ethereum Format

- **G1 Point:** 128 bytes (uncompressed)
  - 64 bytes x-coordinate (first 16 bytes are zero padding)
  - 64 bytes y-coordinate (first 16 bytes are zero padding)
- **G2 Point:** 256 bytes (uncompressed)
  - 128 bytes x-coordinate (C1, C0 components)
  - 128 bytes y-coordinate (C1, C0 components)
- **Scalar:** 32 bytes (big-endian)

## Integration with test_bls12381_multiexp_enhanced.sh

This program is automatically called by the test script:

- **Random mode** - Used for `g1` and `g2` test types
- **Ethereum mode** - Used for `ethereum-g1` and `ethereum-g2` test types

The script parses the output and updates `Bls12381MultiExpHelper.cs` automatically.

## Error Handling

The program validates:

- Point format and length
- Scalar values (must be positive integers)
- Ethereum format padding bytes
- Input hex string validity

On error, the program prints an error message and exits with code 1.

## Notes

- Random mode generates cryptographically secure random points and scalars
- Manual mode is useful for reproducing specific test cases
- Ethereum mode is designed for compatibility with Neo's Ethereum test vectors
- All output uses big-endian byte order (matching Neo's implementation)

