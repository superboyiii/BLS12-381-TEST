# Bls12381MultiExpHelper.cs

C# helper program that generates Neo VM scripts for BLS12-381 MultiExp operations. Takes configured points and scalars, and produces executable Neo VM bytecode.

## Features

- Generate Neo VM scripts for `bls12381MultiExp` calls
- Support G1 and G2 curve operations
- Support multiple different points or single point repetition
- Output Base64 and hexadecimal script encodings
- Ready for Neo RPC `invokescript` calls

## Prerequisites

- **.NET SDK 9.0** - Required to compile and run the program
- **Neo SDK** - Neo blockchain SDK (referenced via project dependencies)

## Configuration

Edit the configuration section at the top of the file before running:

### Points Configuration

**G1 Points Array:**
```csharp
private static readonly string[] G1_POINTS = new string[]
{
    "a195fab58325ffd54c08d3b180d2275ca2b45ab91623a5d6b330d88d25f0754b7259e710636296e583c8be33e968860d",
    // Add more G1 points here if needed
};
```

- Each point must be **96 hex characters** (48 bytes, compressed format)
- If array is empty, falls back to `G1_HEX` (single point mode)
- Multiple points will cycle through for each scalar pair

**G2 Points Array:**
```csharp
private static readonly string[] G2_POINTS = new string[]
{
    "a4eaf10f48781d663bf03d046d50c902088b97cd35ccbdd3fffbc2ee5cd95dc00c8894dbc84a3390cd95dcbf50ef9ece176b5efc0cba714ae43df47dd9d408daa5852cd6b47ccc2e504c7ad3e0829196d1e5a4d381edf08f8067a88c25dda003",
    // Add more G2 points here if needed
};
```

- Each point must be **192 hex characters** (96 bytes, compressed format)
- If array is empty, falls back to `G2_HEX` (single point mode)

### Scalars Configuration

```csharp
private static readonly BigInteger[] SCALARS = new BigInteger[] 
{ 
    1583818600, 259712423, 351930380, /* ... */ 
};
```

- Each scalar corresponds to one point-scalar pair
- MultiExp calculation: `point₁ × scalar₁ + point₂ × scalar₂ + ...`
- Number of scalars determines the number of pairs

### Curve Selection

```csharp
private static readonly bool USE_G2 = false;
```

- `false` - Use G1 curve (default)
- `true` - Use G2 curve

### Legacy Single Point (Backward Compatibility)

If `G1_POINTS` or `G2_POINTS` arrays are empty, these single point values are used:

```csharp
private static readonly string G1_HEX = "a195fab58325ffd54c08d3b180d2275ca2b45ab91623a5d6b330d88d25f0754b7259e710636296e583c8be33e968860d";
private static readonly string G2_HEX = "a4eaf10f48781d663bf03d046d50c902088b97cd35ccbdd3fffbc2ee5cd95dc00c8894dbc84a3390cd95dcbf50ef9ece176b5efc0cba714ae43df47dd9d408daa5852cd6b47ccc2e504c7ad3e0829196d1e5a4d381edf08f8067a88c25dda003";
```

## Usage

### Step 1: Update Configuration

1. Obtain test data from `pairing_gen.go` output
2. Copy the generated C# code snippets into this file:
   - Update `G1_POINTS`/`G2_POINTS` arrays or `G1_HEX`/`G2_HEX`
   - Update `SCALARS` array
   - Set `USE_G2` flag if needed

### Step 2: Compile and Run

```bash
# Compile and run
dotnet run --project Bls12381MultiExpHelper.csproj

# Or build first, then run
dotnet build
dotnet run
```

### Step 3: Use Generated Script

The program outputs:

1. **Base64 encoding** - For Neo CLI `invokescript` command
2. **Hexadecimal encoding** - Alternative format
3. **Usage instructions** - Ready-to-use commands

## Output Example

```
=== Bls12381MultiExp Call Script Generated ===

Using G1 points, 5 pairs
  Unique points: 1 (will cycle through for 5 pairs)
Scalar values: [1, 2, 3, 4, 5]

Base64 encoding (for Neo CLI):
DAABAAIAAQwAAQACAAEAAwABAAQAAQAFAAEABgABAAcAAQAIAAEACQABAAoAAQALAAEADAA...

Hexadecimal encoding:
0D000100020001000100030001000400010005000100060001000700010008000100090001000A0001000B0001000C00...

Usage in Neo CLI:
invoke script DAABAAIAAQwAAQACAAEAAwABAAQAAQAFAAEABgABAAcAAQAIAAEACQABAAoAAQALAAEADAA...
```

## Integration with test_bls12381_multiexp_enhanced.sh

This program is automatically called by the test script:

1. Script runs `pairing_gen.go` to generate test data
2. Script updates this file's configuration automatically
3. Script runs this program to generate Neo VM script
4. Script calls Neo RPC with generated script
5. Script compares results

**Note:** The test script automatically restores this file to its original state after execution.

## Script Generation Details

The generated script performs:

1. **Deserialize Points** - Converts compressed hex points to BLS12-381 point objects
2. **Create Pairs** - Constructs `[point, scalar]` pairs for each input
3. **Pack Pairs** - Creates array of all pairs
4. **Call MultiExp** - Invokes `CryptoLib.bls12381MultiExp(pairs)`
5. **Serialize Result** - Converts result point back to compressed format

### Stack Operations

- Pushes scalar bytes (32 bytes, big-endian)
- Calls `bls12381Deserialize` to convert point hex to point object
- Packs `[point, scalar]` pair
- Packs all pairs into array
- Calls `bls12381MultiExp` with pairs array
- Calls `bls12381Serialize` to get compressed result

## Validation

The program validates:

- At least one scalar must be provided
- Points must have correct length (96 chars for G1, 192 chars for G2)
- All points in array must have consistent length
- Configuration must match selected curve (G1 vs G2)

## Error Messages

- **"Please provide at least one scalar value!"** - `SCALARS` array is empty
- **"Please provide at least one G1/G2 point!"** - No points configured
- **"Point at index X has invalid length"** - Point hex string has wrong length
- **"Unable to encode scalar value"** - Scalar value exceeds 256 bits

## Scalar Selection Guide

For different use cases:

1. **Testing/Demo** - Use simple values: `[1, 2, 3]` or `[1, 1, 1]`
2. **Equal Weights** - All same value: `[10, 10, 10]`
3. **Weighted Distribution** - Different weights: `[10, 5, 1]`
4. **BLS Signature Aggregation** - Use hash values as scalars
5. **Security Applications** - Use cryptographically random scalars

See `SCALAR_SELECTION_GUIDE.md` for more details.

## Notes

- Points are in **compressed format** (48 bytes for G1, 96 bytes for G2)
- Scalars are encoded as **32-byte big-endian** values
- The script uses Neo's `CryptoLib` contract for BLS12-381 operations
- Multiple points will cycle through if there are more scalars than points
- Single point mode repeats the same point for all scalar pairs

