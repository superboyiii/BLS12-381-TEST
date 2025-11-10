package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// BLS12-381 base field modulus p
// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
var bls12_381_p, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)

// bls12_381_p_half = (p-1)/2
var bls12_381_p_half = new(big.Int)

func init() {
	// Calculate (p-1)/2
	bls12_381_p_half.Sub(bls12_381_p, big.NewInt(1))
	bls12_381_p_half.Rsh(bls12_381_p_half, 1)
}

// isLexicographicallyLargestFp checks if an Fp element (48 bytes, big-endian) is lexicographically largest
// This matches Neo C# Fp.LexicographicallyLargest() implementation
// An element is lexicographically largest if it is greater than (p-1)/2
// Note: yBytes is in big-endian format (as returned by gnark-crypto Marshal())
// Neo uses constant 0xdcff_7fff_ffff_d556 which is (p-1)/2 + 1, and checks t >= constant
// This means t > (p-1)/2, which is equivalent to y > (p-1)/2
func isLexicographicallyLargestFp(yBytes []byte) bool {
	if len(yBytes) != 48 {
		return false
	}
	// gnark-crypto Marshal() returns big-endian format
	// big.Int.SetBytes() interprets bytes as big-endian, so we can use directly
	y := new(big.Int).SetBytes(yBytes)
	// Compare with (p-1)/2
	// Neo uses (p-1)/2 + 1 and checks t >= constant, which is equivalent to t > (p-1)/2
	return y.Cmp(bls12_381_p_half) > 0
}

// isLexicographicallyLargestFp2 checks if an Fp2 element (96 bytes, big-endian) is lexicographically largest
// This matches Neo C# Fp2.LexicographicallyLargest() implementation
// An Fp2 element is lexicographically largest if:
//   - C1 is lexicographically largest, OR
//   - C1 is zero AND C0 is lexicographically largest
//
// Note: yBytes format from gnark-crypto G2 Marshal() is [y.C1 (48 bytes) + y.C0 (48 bytes)] in big-endian
func isLexicographicallyLargestFp2(yBytes []byte) bool {
	if len(yBytes) != 96 {
		return false
	}
	// Extract C1 (first 48 bytes) and C0 (last 48 bytes)
	// Format: [y.C1 (big-endian, 48 bytes) + y.C0 (big-endian, 48 bytes)]
	c1Bytes := yBytes[0:48]
	c0Bytes := yBytes[48:96]

	// Check if C1 is lexicographically largest
	c1IsLargest := isLexicographicallyLargestFp(c1Bytes)
	if c1IsLargest {
		return true
	}

	// Check if C1 is zero
	c1IsZero := true
	for _, b := range c1Bytes {
		if b != 0 {
			c1IsZero = false
			break
		}
	}

	// If C1 is zero, check if C0 is lexicographically largest
	if c1IsZero {
		return isLexicographicallyLargestFp(c0Bytes)
	}

	return false
}

// randomOnG1 generates a random G1 point (similar to RandomOnG2)
func randomOnG1() (bls.G1Affine, error) {
	g1GenJac, _, _, _ := bls.Generators()
	var scalar fr.Element
	if _, err := scalar.SetRandom(); err != nil {
		return bls.G1Affine{}, err
	}
	var g1Jac bls.G1Jac
	g1Jac.ScalarMultiplication(&g1GenJac, scalar.BigInt(new(big.Int)))
	var P bls.G1Affine
	P.FromJacobian(&g1Jac)
	return P, nil
}

// computeMultiExpFromEthereumFormat computes MultiExp result from Ethereum format (uncompressed) G1/G2 point and scalars
// This function is convenient for using Neo's Ethereum test vectors directly
// Parameters:
//   - inputHex: Ethereum format input (for G1: 160 bytes = 128 bytes point + 32 bytes scalar per pair)
//   - useG2: true for G2, false for G1
//
// Returns: Compressed result point in hex string
func computeMultiExpFromEthereumFormat(inputHex string, useG2 bool) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}

	if useG2 {
		// G2 format: 288 bytes per pair = 256 bytes point + 32 bytes scalar
		if len(inputBytes)%288 != 0 {
			return "", fmt.Errorf("G2 input length must be multiple of 288 bytes, got %d", len(inputBytes))
		}

		var points []bls.G2Affine
		var scalars []*big.Int

		for offset := 0; offset < len(inputBytes); offset += 288 {
			pointBytes := inputBytes[offset : offset+256]
			scalarBytes := inputBytes[offset+256 : offset+288]

			// Parse G2 point from Ethereum format (256 bytes)
			g2Point, err := parseEthereumG2PointFromBytes(pointBytes)
			if err != nil {
				return "", fmt.Errorf("failed to parse G2 point at offset %d: %v", offset, err)
			}

			scalar := parseEthereumScalarFromBytes(scalarBytes)
			points = append(points, g2Point)
			scalars = append(scalars, scalar)
		}

		// Compute MultiExp: point1 × scalar1 + point2 × scalar2 + ...
		var resultJac bls.G2Jac
		for i := 0; i < len(points); i++ {
			var g2Jac bls.G2Jac
			g2Jac.FromAffine(&points[i])
			var tempJac bls.G2Jac
			tempJac.ScalarMultiplication(&g2Jac, scalars[i])
			if i == 0 {
				resultJac.Set(&tempJac)
			} else {
				resultJac.AddAssign(&tempJac)
			}
		}
		var resultAffine bls.G2Affine
		resultAffine.FromJacobian(&resultJac)

		resultCompressed := convertG2AffineToCompressed(resultAffine)
		return hex.EncodeToString(resultCompressed), nil
	} else {
		// G1 format: 160 bytes per pair = 128 bytes point + 32 bytes scalar
		if len(inputBytes)%160 != 0 {
			return "", fmt.Errorf("G1 input length must be multiple of 160 bytes, got %d", len(inputBytes))
		}

		var points []bls.G1Affine
		var scalars []*big.Int

		for offset := 0; offset < len(inputBytes); offset += 160 {
			pointBytes := inputBytes[offset : offset+128]
			scalarBytes := inputBytes[offset+128 : offset+160]

			// Parse G1 point from Ethereum format (128 bytes)
			g1Point, err := parseEthereumG1PointFromBytes(pointBytes)
			if err != nil {
				return "", fmt.Errorf("failed to parse G1 point at offset %d: %v", offset, err)
			}

			scalar := parseEthereumScalarFromBytes(scalarBytes)
			points = append(points, g1Point)
			scalars = append(scalars, scalar)
		}

		// Compute MultiExp: point1 × scalar1 + point2 × scalar2 + ...
		var resultJac bls.G1Jac
		for i := 0; i < len(points); i++ {
			var g1Jac bls.G1Jac
			g1Jac.FromAffine(&points[i])
			var tempJac bls.G1Jac
			tempJac.ScalarMultiplication(&g1Jac, scalars[i])
			if i == 0 {
				resultJac.Set(&tempJac)
			} else {
				resultJac.AddAssign(&tempJac)
			}
		}
		var resultAffine bls.G1Affine
		resultAffine.FromJacobian(&resultJac)

		resultCompressed := convertG1AffineToCompressed(resultAffine)
		return hex.EncodeToString(resultCompressed), nil
	}
}

// computeMultiExpFromCompressed computes MultiExp result from compressed G1/G2 point and scalars
// This function uses gnark-crypto API directly, independent of C# implementation logic
// Parameters:
//   - pointHex: Compressed G1 (96 hex chars) or G2 (192 hex chars) point in hex string
//   - scalars: Array of scalar values (BigInteger values)
//   - useG2: true for G2, false for G1
//
// Returns: Compressed result point in hex string
func computeMultiExpFromCompressed(pointHex string, scalars []*big.Int, useG2 bool) (string, error) {
	// Parse hex string to bytes
	pointHex = strings.TrimSpace(pointHex)
	pointBytes, err := hex.DecodeString(pointHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse point hex: %v", err)
	}

	if useG2 {
		// G2 MultiExp
		if len(pointBytes) != 96 {
			return "", fmt.Errorf("G2 point must be 96 bytes (compressed), got %d", len(pointBytes))
		}

		// Deserialize compressed G2 point
		var g2Affine bls.G2Affine
		if _, err := g2Affine.SetBytes(pointBytes); err != nil {
			return "", fmt.Errorf("failed to deserialize G2 point: %v", err)
		}

		// Convert to Jacobian for efficient operations
		var g2Jac bls.G2Jac
		g2Jac.FromAffine(&g2Affine)

		// Compute MultiExp: point × scalar₁ + point × scalar₂ + ... = point × (scalar₁ + scalar₂ + ...)
		// For proper MultiExp, we should compute: point₁ × scalar₁ + point₂ × scalar₂ + ...
		// But if all points are the same, we can optimize: point × (scalar₁ + scalar₂ + ...)
		// However, for comparison purposes, we'll compute each multiplication separately and add them
		var resultG2Jac bls.G2Jac
		resultG2Jac.Set(&g2Jac)
		resultG2Jac.ScalarMultiplication(&g2Jac, scalars[0])

		// Add remaining point × scalar pairs
		for i := 1; i < len(scalars); i++ {
			var tempG2Jac bls.G2Jac
			tempG2Jac.ScalarMultiplication(&g2Jac, scalars[i])
			resultG2Jac.AddAssign(&tempG2Jac)
		}

		// Convert back to Affine
		var resultG2 bls.G2Affine
		resultG2.FromJacobian(&resultG2Jac)

		// Serialize to compressed format
		g2ResultUncompressed := resultG2.Marshal()
		if len(g2ResultUncompressed) != 192 {
			return "", fmt.Errorf("unexpected G2 uncompressed length: %d", len(g2ResultUncompressed))
		}

		// Convert to compressed format (96 bytes)
		g2ResultCompressed := make([]byte, 96)
		copy(g2ResultCompressed, g2ResultUncompressed[:96]) // Extract x coordinate
		g2ResultCompressed[0] |= 0x80                       // Set compression flag

		// Set y coordinate sort flag using lexicographically largest check
		yBytes := g2ResultUncompressed[96:192]
		if isLexicographicallyLargestFp2(yBytes) {
			g2ResultCompressed[0] |= 0x20
		}

		return fmt.Sprintf("%x", g2ResultCompressed), nil
	} else {
		// G1 MultiExp
		if len(pointBytes) != 48 {
			return "", fmt.Errorf("G1 point must be 48 bytes (compressed), got %d", len(pointBytes))
		}

		// Deserialize compressed G1 point
		var g1Affine bls.G1Affine
		if _, err := g1Affine.SetBytes(pointBytes); err != nil {
			return "", fmt.Errorf("failed to deserialize G1 point: %v", err)
		}

		// Convert to Jacobian for efficient operations
		var g1Jac bls.G1Jac
		g1Jac.FromAffine(&g1Affine)

		// Compute MultiExp: point × scalar₁ + point × scalar₂ + ... = point × (scalar₁ + scalar₂ + ...)
		// For proper MultiExp, we should compute: point₁ × scalar₁ + point₂ × scalar₂ + ...
		// But if all points are the same, we can optimize: point × (scalar₁ + scalar₂ + ...)
		// However, for comparison purposes, we'll compute each multiplication separately and add them
		var resultG1Jac bls.G1Jac
		resultG1Jac.Set(&g1Jac)
		resultG1Jac.ScalarMultiplication(&g1Jac, scalars[0])

		// Add remaining point × scalar pairs
		for i := 1; i < len(scalars); i++ {
			var tempG1Jac bls.G1Jac
			tempG1Jac.ScalarMultiplication(&g1Jac, scalars[i])
			resultG1Jac.AddAssign(&tempG1Jac)
		}

		// Convert back to Affine
		var resultG1 bls.G1Affine
		resultG1.FromJacobian(&resultG1Jac)

		// Serialize to compressed format
		g1ResultUncompressed := resultG1.Marshal()
		if len(g1ResultUncompressed) != 96 {
			return "", fmt.Errorf("unexpected G1 uncompressed length: %d", len(g1ResultUncompressed))
		}

		// Convert to compressed format (48 bytes)
		g1ResultCompressed := make([]byte, 48)
		copy(g1ResultCompressed, g1ResultUncompressed[:48]) // Extract x coordinate
		g1ResultCompressed[0] |= 0x80                       // Set compression flag

		// Set y coordinate sort flag using lexicographically largest check
		yBytes := g1ResultUncompressed[48:96]
		if isLexicographicallyLargestFp(yBytes) {
			g1ResultCompressed[0] |= 0x20
		}

		return fmt.Sprintf("%x", g1ResultCompressed), nil
	}
}

// runRandomMode runs the random generation mode
// This generates random G1/G2 points and scalars, then computes MultiExp
// useG2: true for G2, false for G1
func runRandomMode(maxScalars int, useG2 bool) {
	// Generate random G1 point
	P, err := randomOnG1()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G1 point: %v", err))
	}

	// Generate random G2 point
	Q, err := bls.RandomOnG2()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G2 point: %v", err))
	}

	// Compute pairing: Pair function accepts slices
	result, err := bls.Pair([]bls.G1Affine{P}, []bls.G2Affine{Q})
	if err != nil {
		panic(fmt.Sprintf("pairing failed: %v", err))
	}

	// gnark-crypto's Marshal() method:
	// - G1: returns uncompressed format (96 bytes = 48 bytes x + 48 bytes y)
	// - G2: returns uncompressed format (192 bytes)
	//
	// Neo's Bls12381Deserialize expects:
	// - G1: compressed format (48 bytes)
	// - G2: compressed format (96 bytes)

	// G1 compressed format: 48 bytes
	// Compressed format: x coordinate (48 bytes) + flags
	// Flags:
	//   - MSB (0x80): compression flag (must be set)
	//   - 2nd bit (0x40): point at infinity flag
	//   - 3rd bit (0x20): y coordinate sort flag
	g1Uncompressed := P.Marshal()
	if len(g1Uncompressed) == 96 {
		// Extract x coordinate (first 48 bytes)
		g1Compressed := make([]byte, 48)
		copy(g1Compressed, g1Uncompressed[:48])

		// Set compression flag (MSB)
		g1Compressed[0] |= 0x80

		// Check if point is at infinity (in gnark-crypto, if x and y are both 0, it might be infinity)
		// Note: This is simplified handling, actual implementation may need more precise checking

		// Extract y coordinate to determine sort flag using lexicographically largest check
		yBytes := g1Uncompressed[48:96]
		if isLexicographicallyLargestFp(yBytes) {
			g1Compressed[0] |= 0x20 // Set sort flag
		}

		fmt.Printf("G1 (compressed, 48 bytes): %x\n", g1Compressed)
		fmt.Printf("G1 (uncompressed, 96 bytes): %x\n", g1Uncompressed)
	} else {
		fmt.Printf("G1: %x\n", g1Uncompressed)
	}

	// G2 format conversion
	// gnark-crypto's Marshal() returns uncompressed format for G2 (192 bytes = 384 hex characters)
	// Neo requires compressed format (96 bytes = 192 hex characters)
	g2Uncompressed := Q.Marshal()
	if len(g2Uncompressed) == 192 {
		// Uncompressed format: first 96 bytes are x coordinate (x.C1 + x.C0), last 96 bytes are y coordinate
		// Compressed format: use only x coordinate (96 bytes) and add flags
		g2Compressed := make([]byte, 96)
		copy(g2Compressed, g2Uncompressed[:96]) // Extract x coordinate

		// Set compression flag (MSB)
		g2Compressed[0] |= 0x80

		// Extract y coordinate to determine sort flag using lexicographically largest check
		yBytes := g2Uncompressed[96:192]
		if isLexicographicallyLargestFp2(yBytes) {
			g2Compressed[0] |= 0x20 // Set sort flag
		}

		fmt.Printf("G2 (compressed, 96 bytes): %x\n", g2Compressed)
		fmt.Printf("G2 (uncompressed, 192 bytes): %x\n", g2Uncompressed)
	} else {
		fmt.Printf("G2: %x\n", g2Uncompressed)
	}

	fmt.Printf("Pairing result: %x\n", result.Marshal())

	// ============================================
	// Compute MultiExp result for comparison with Neo invokescript result
	// ============================================
	// Generate random scalars according to BLS12-381 standard (gnark-crypto)
	// BLS12-381 fr field modulus: r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
	// Scalar range: [0, r-1] (255-bit prime field)

	minScalars := 1

	// Randomly generate number of scalars between 1 and maxScalars
	// Use fr.Element to generate random number count
	var countScalar fr.Element
	if _, err := countScalar.SetRandom(); err != nil {
		panic(fmt.Sprintf("failed to generate random count: %v", err))
	}
	// Convert fr.Element to big.Int and use Mod to get value in range [0, maxScalars-minScalars]
	countBig := countScalar.BigInt(new(big.Int))
	rangeSize := big.NewInt(int64(maxScalars - minScalars + 1))
	modResult := new(big.Int).Mod(countBig, rangeSize)
	countInt := int(modResult.Int64())
	numScalars := countInt + minScalars
	if numScalars < minScalars {
		numScalars = minScalars
	}
	if numScalars > maxScalars {
		numScalars = maxScalars
	}

	scalars := make([]*big.Int, numScalars)

	// Generate multiple different points for comprehensive testing
	// Option: Generate one point per scalar, or use fewer points that cycle
	// For now, generate one point per scalar to test different points scenario
	numPoints := numScalars
	useMultiplePoints := true // Set to false to use single point (backward compatibility)

	if !useMultiplePoints {
		numPoints = 1
	}

	// C# int.MaxValue = 2,147,483,647 = 2^31 - 1
	// Limit scalar values to [0, int.MaxValue] for C# compatibility
	csharpIntMaxValue := big.NewInt(2147483647) // int.MaxValue

	fmt.Println("\n=== Generating Random Scalars (BLS12-381 Standard) ===")
	fmt.Printf("Max scalars limit: %d\n", maxScalars)
	fmt.Printf("Number of scalars: %d (randomly generated in range: %d-%d)\n", numScalars, minScalars, maxScalars)
	fmt.Printf("Scalar value range: [0, %s] (limited to C# int.MaxValue for compatibility)\n", csharpIntMaxValue.String())
	fmt.Println("Using gnark-crypto fr.Element for standard-compliant generation")

	if useMultiplePoints {
		fmt.Printf("\n=== Generating Multiple Different Points ===\n")
		fmt.Printf("Number of unique points: %d (one per scalar for comprehensive testing)\n", numPoints)
	} else {
		fmt.Printf("\n=== Using Single Point (repeated for all scalars) ===\n")
	}

	// Generate points
	g1Points := make([]bls.G1Affine, numPoints)
	g2Points := make([]bls.G2Affine, numPoints)

	for i := 0; i < numPoints; i++ {
		if i == 0 {
			// First point: use the already generated P and Q
			g1Points[i] = P
			g2Points[i] = Q
		} else {
			// Generate additional random points
			newP, err := randomOnG1()
			if err != nil {
				panic(fmt.Sprintf("failed to generate random G1 point %d: %v", i, err))
			}
			g1Points[i] = newP

			newQ, err := bls.RandomOnG2()
			if err != nil {
				panic(fmt.Sprintf("failed to generate random G2 point %d: %v", i, err))
			}
			g2Points[i] = newQ
		}
	}

	for i := 0; i < numScalars; i++ {
		// Use gnark-crypto's fr.Element to generate standard-compliant random scalar
		var scalar fr.Element
		if _, err := scalar.SetRandom(); err != nil {
			panic(fmt.Sprintf("failed to generate random scalar: %v", err))
		}
		// Convert fr.Element to big.Int
		scalarBig := scalar.BigInt(new(big.Int))

		// Limit scalar value to [0, int.MaxValue] for C# compatibility
		// Use Mod to get value in range [0, int.MaxValue]
		// Mod divisor = int.MaxValue + 1 to get range [0, int.MaxValue]
		modDivisor := new(big.Int).Add(csharpIntMaxValue, big.NewInt(1))
		scalarBig.Mod(scalarBig, modDivisor)

		// Ensure scalar is not zero, as MultiExp skips zero scalars
		if scalarBig.Sign() == 0 {
			scalarBig.SetInt64(1) // Set to 1 if it's zero
		}

		scalars[i] = scalarBig
		fmt.Printf("Scalar[%d]: %s\n", i, scalars[i].String())
	}

	// Output scalars in C# array format for easy copy-paste
	fmt.Println("\n=== C# Array Format (copy to Bls12381MultiExpHelper.cs) ===")
	fmt.Print("private static readonly BigInteger[] SCALARS = new BigInteger[] { ")
	for i, s := range scalars {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(s.String())
	}
	fmt.Println(" };")

	// Output points in C# array format
	if useMultiplePoints {
		fmt.Println("\n=== G1 Points Array Format (copy to Bls12381MultiExpHelper.cs) ===")
		fmt.Printf("// Total points: %d (should match number of scalars: %d)\n", len(g1Points), len(scalars))
		fmt.Print("private static readonly string[] G1_POINTS = new string[]\n{\n")
		for i, p := range g1Points {
			g1Uncompressed := p.Marshal()
			if len(g1Uncompressed) == 96 {
				g1Compressed := make([]byte, 48)
				copy(g1Compressed, g1Uncompressed[:48])
				g1Compressed[0] |= 0x80
				yBytes := g1Uncompressed[48:96]
				if isLexicographicallyLargestFp(yBytes) {
					g1Compressed[0] |= 0x20
				}
				fmt.Printf("    \"%x\"%s  // Point[%d], will be used with Scalar[%d] = %s\n", g1Compressed, func() string {
					if i < len(g1Points)-1 {
						return ","
					}
					return ""
				}(), i, i, scalars[i].String())
			}
		}
		fmt.Println("};")

		fmt.Println("\n=== G2 Points Array Format (copy to Bls12381MultiExpHelper.cs) ===")
		fmt.Printf("// Total points: %d (should match number of scalars: %d)\n", len(g2Points), len(scalars))
		fmt.Print("private static readonly string[] G2_POINTS = new string[]\n{\n")
		for i, q := range g2Points {
			g2Uncompressed := q.Marshal()
			if len(g2Uncompressed) == 192 {
				g2Compressed := make([]byte, 96)
				copy(g2Compressed, g2Uncompressed[:96])
				g2Compressed[0] |= 0x80
				yBytes := g2Uncompressed[96:192]
				if isLexicographicallyLargestFp2(yBytes) {
					g2Compressed[0] |= 0x20
				}
				fmt.Printf("    \"%x\"%s  // Point[%d], will be used with Scalar[%d] = %s\n", g2Compressed, func() string {
					if i < len(g2Points)-1 {
						return ","
					}
					return ""
				}(), i, i, scalars[i].String())
			}
		}
		fmt.Println("};")
	} else {
		// Single point format (backward compatibility)
		fmt.Println("\n=== Single Point Format (backward compatibility) ===")
	}

	fmt.Println("\n=== MultiExp Calculation Result ===")
	fmt.Printf("Using %s points\n", func() string {
		if useG2 {
			return "G2"
		}
		return "G1"
	}())
	if useG2 {
		// G2 MultiExp: point1 × scalar1 + point2 × scalar2 + ...
		var resultG2Jac bls.G2Jac
		fmt.Printf("\n=== G2 MultiExp Calculation Details ===\n")
		for i := 0; i < len(scalars); i++ {
			pointIdx := i
			if !useMultiplePoints {
				pointIdx = 0 // Use first point for all scalars
			} else {
				pointIdx = i % numPoints // Cycle through points
			}

			// Output point and scalar for this iteration
			g2PointCompressed := convertG2AffineToCompressed(g2Points[pointIdx])
			fmt.Printf("  Pair[%d]: point[%d] = %x, scalar = %s\n", i, pointIdx, g2PointCompressed, scalars[i].String())

			var g2Jac bls.G2Jac
			g2Jac.FromAffine(&g2Points[pointIdx])
			var tempJac bls.G2Jac
			tempJac.ScalarMultiplication(&g2Jac, scalars[i])
			if i == 0 {
				resultG2Jac.Set(&tempJac)
			} else {
				resultG2Jac.AddAssign(&tempJac)
			}
		}
		var resultG2 bls.G2Affine
		resultG2.FromJacobian(&resultG2Jac)

		// Serialize G2 result
		g2ResultUncompressed := resultG2.Marshal()
		if len(g2ResultUncompressed) == 192 {
			g2ResultCompressed := make([]byte, 96)
			copy(g2ResultCompressed, g2ResultUncompressed[:96])
			g2ResultCompressed[0] |= 0x80
			yBytes := g2ResultUncompressed[96:192]
			if isLexicographicallyLargestFp2(yBytes) {
				g2ResultCompressed[0] |= 0x20
			}
			fmt.Printf("G2 MultiExp result (compressed, 96 bytes): %x\n", g2ResultCompressed)
			fmt.Printf("Expected result (for comparison with Neo invokescript): %x\n", g2ResultCompressed)
		}
	} else {
		// G1 MultiExp: point1 × scalar1 + point2 × scalar2 + ...
		var resultG1Jac bls.G1Jac
		fmt.Printf("\n=== G1 MultiExp Calculation Details ===\n")
		for i := 0; i < len(scalars); i++ {
			pointIdx := i
			if !useMultiplePoints {
				pointIdx = 0 // Use first point for all scalars
			} else {
				pointIdx = i % numPoints // Cycle through points
			}

			// Output point and scalar for this iteration
			g1PointCompressed := convertG1AffineToCompressed(g1Points[pointIdx])
			fmt.Printf("  Pair[%d]: point[%d] = %x, scalar = %s\n", i, pointIdx, g1PointCompressed, scalars[i].String())

			var g1Jac bls.G1Jac
			g1Jac.FromAffine(&g1Points[pointIdx])
			var tempJac bls.G1Jac
			tempJac.ScalarMultiplication(&g1Jac, scalars[i])
			if i == 0 {
				resultG1Jac.Set(&tempJac)
			} else {
				resultG1Jac.AddAssign(&tempJac)
			}
		}
		var resultG1 bls.G1Affine
		resultG1.FromJacobian(&resultG1Jac)

		// Serialize G1 result
		g1ResultUncompressed := resultG1.Marshal()
		if len(g1ResultUncompressed) == 96 {
			g1ResultCompressed := make([]byte, 48)
			copy(g1ResultCompressed, g1ResultUncompressed[:48])
			g1ResultCompressed[0] |= 0x80
			yBytes := g1ResultUncompressed[48:96]
			if isLexicographicallyLargestFp(yBytes) {
				g1ResultCompressed[0] |= 0x20
			}
			fmt.Printf("G1 MultiExp result (compressed, 48 bytes): %x\n", g1ResultCompressed)
			fmt.Printf("Expected result (for comparison with Neo invokescript): %x\n", g1ResultCompressed)
		}
	}

}

// runEthereumMode runs the Ethereum format calculation mode
// This computes MultiExp from Ethereum format (uncompressed) input
// Input format: For G1, 160 bytes per pair (128 bytes point + 32 bytes scalar)
//
//	For G2, 288 bytes per pair (256 bytes point + 32 bytes scalar)
func runEthereumMode(inputHex string, useG2 bool) error {
	inputHex = strings.TrimSpace(inputHex)
	if inputHex == "" {
		return fmt.Errorf("input hex is required")
	}

	fmt.Printf("Using Ethereum format input\n")
	if useG2 {
		fmt.Printf("Expected format: 288 bytes per pair (256 bytes G2 point + 32 bytes scalar)\n")
	} else {
		fmt.Printf("Expected format: 160 bytes per pair (128 bytes G1 point + 32 bytes scalar)\n")
	}
	fmt.Printf("Input hex length: %d characters\n", len(inputHex))

	// Compute MultiExp using Ethereum format
	fmt.Println("\n=== Computing MultiExp using Ethereum format ===")
	result, err := computeMultiExpFromEthereumFormat(inputHex, useG2)
	if err != nil {
		return fmt.Errorf("failed to compute MultiExp: %v", err)
	}

	expectedLength := 96
	if useG2 {
		expectedLength = 192
	}
	fmt.Printf("MultiExp result (compressed, %d hex chars): %s\n", expectedLength, result)
	fmt.Println("This result can be compared with Neo invokescript output")

	return nil
}

// runManualMode runs the manual calculation mode
// This computes MultiExp from manually provided compressed G1/G2 point and scalars
func runManualMode(g1Hex, g2Hex string, scalarsStr string, useG2 bool) error {
	// Parse scalars
	// Note: scalarsStr should be comma-separated, e.g., "123,456,789"
	// If using spaces, wrap the entire string in quotes: --scalars "123, 456, 789"
	scalarStrs := strings.Split(scalarsStr, ",")
	scalars := make([]*big.Int, 0, len(scalarStrs))
	for i, s := range scalarStrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		scalar, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("invalid scalar at index %d: '%s' (hint: ensure all scalars are comma-separated and wrapped in quotes if they contain spaces)", i, s)
		}
		scalars = append(scalars, scalar)
	}

	if len(scalars) == 0 {
		return fmt.Errorf("no valid scalars provided (hint: use --scalars \"val1,val2,val3\" with quotes)")
	}

	// Warn if only one scalar was parsed but input contains comma (might indicate missing quotes)
	// This happens when shell splits the argument before passing to the program
	if len(scalars) == 1 {
		// Check if the original input might have had more scalars
		// If scalarsStr doesn't contain comma but user likely intended multiple scalars,
		// we can't detect it here, but we can at least show the count
		if !strings.Contains(scalarsStr, ",") {
			fmt.Fprintf(os.Stderr, "Note: Only 1 scalar provided. If you intended multiple scalars, wrap them in quotes:\n")
			fmt.Fprintf(os.Stderr, "  --scalars \"val1,val2,val3\" (with quotes)\n")
		}
	}

	// Determine which point to use
	var pointHex string
	if useG2 {
		if g2Hex == "" {
			return fmt.Errorf("G2 point is required when using --use-g2")
		}
		pointHex = strings.TrimSpace(g2Hex)
		fmt.Printf("Using G2 point (compressed, 96 bytes, 192 hex chars): %s\n", pointHex)
	} else {
		if g1Hex == "" {
			return fmt.Errorf("G1 point is required (use --g1 or --use-g2 with --g2)")
		}
		pointHex = strings.TrimSpace(g1Hex)
		fmt.Printf("Using G1 point (compressed, 48 bytes, 96 hex chars): %s\n", pointHex)
	}

	fmt.Printf("Using scalars (%d total): %v\n", len(scalars), scalars)

	// Compute MultiExp using computeMultiExpFromCompressed function
	fmt.Println("\n=== Computing MultiExp using gnark-crypto API ===")
	result, err := computeMultiExpFromCompressed(pointHex, scalars, useG2)
	if err != nil {
		return fmt.Errorf("failed to compute MultiExp: %v", err)
	}

	expectedLength := 96
	if useG2 {
		expectedLength = 192
	}
	fmt.Printf("MultiExp result (compressed, %d hex chars): %s\n", expectedLength, result)
	fmt.Println("This result can be compared with Neo invokescript output")

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  Random mode (default):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go [max_scalars]\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go random [max_scalars]\n")
	fmt.Fprintf(os.Stderr, "      - max_scalars: Maximum number of scalars (default: 128)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Manual mode (compressed format):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go manual --g1 <hex> --scalars \"<scalar1,scalar2,...>\"\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go manual --g2 <hex> --scalars \"<scalar1,scalar2,...>\" --use-g2\n")
	fmt.Fprintf(os.Stderr, "      - --g1: Compressed G1 point (96 hex chars, 48 bytes)\n")
	fmt.Fprintf(os.Stderr, "      - --g2: Compressed G2 point (192 hex chars, 96 bytes)\n")
	fmt.Fprintf(os.Stderr, "      - --scalars: Comma-separated list of scalar values (MUST be wrapped in quotes)\n")
	fmt.Fprintf(os.Stderr, "      - --use-g2: Use G2 point (default: false, uses G1)\n")
	fmt.Fprintf(os.Stderr, "      Note: Always wrap --scalars value in quotes, e.g., --scalars \"123,456,789\"\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Ethereum mode (uncompressed format, for Neo test vectors):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go ethereum --input <hex> [--use-g2]\n")
	fmt.Fprintf(os.Stderr, "      - --input: Ethereum format input hex string\n")
	fmt.Fprintf(os.Stderr, "        For G1: 160 bytes per pair (128 bytes point + 32 bytes scalar)\n")
	fmt.Fprintf(os.Stderr, "        For G2: 288 bytes per pair (256 bytes point + 32 bytes scalar)\n")
	fmt.Fprintf(os.Stderr, "      - --use-g2: Use G2 format (default: false, uses G1)\n")
	fmt.Fprintf(os.Stderr, "      Example: go run pairing_gen.go ethereum --input <EthG1MultiExpSingleInputHex>\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go 5\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go manual --g1 b2deb4e364cc09aceb924ebe236d28b5d180e27ee0428697f3d088b7c83637820c3c0c95b83189a6301dbaa405792564 --scalars \"1732363698,436226955,507793302,1540421097\"\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go ethereum --input 0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000011\n")
	fmt.Fprintf(os.Stderr, "  Note: In PowerShell, use single quotes or escape: --scalars 'val1,val2' or --scalars \\\"val1,val2\\\"\n")
}

// parseEthereumG1PointFromBytes parses a G1 point from Ethereum format (128 bytes)
// Ethereum format: 64 bytes x (first 16 bytes are 0, last 48 bytes are big-endian) +
//
//	64 bytes y (first 16 bytes are 0, last 48 bytes are big-endian)
func parseEthereumG1PointFromBytes(data []byte) (bls.G1Affine, error) {
	if len(data) != 128 {
		return bls.G1Affine{}, fmt.Errorf("ethereum G1 point must be 128 bytes, got %d", len(data))
	}

	// Check that first 16 bytes of each field element are zero
	for i := 0; i < 16; i++ {
		if data[i] != 0 || data[64+i] != 0 {
			return bls.G1Affine{}, fmt.Errorf("non-zero padding bytes in Ethereum format at positions %d or %d", i, 64+i)
		}
	}

	// Extract x and y (last 48 bytes of each 64-byte field element, big-endian)
	xBytesBE := data[16:64]  // Last 48 bytes of x (big-endian)
	yBytesBE := data[80:128] // Last 48 bytes of y (big-endian)

	// gnark-crypto SetBytes accepts uncompressed format (96 bytes)
	// Format: [x (48 bytes) + y (48 bytes)]
	// Note: gnark-crypto's Marshal() actually returns big-endian format!
	// So we can use Ethereum's big-endian bytes directly
	uncompressedPoint := append(xBytesBE, yBytesBE...)

	var g1Point bls.G1Affine
	bytesRead, err := g1Point.SetBytes(uncompressedPoint)
	if err != nil {
		return bls.G1Affine{}, fmt.Errorf("SetBytes failed: %v", err)
	}
	if bytesRead != 96 {
		return bls.G1Affine{}, fmt.Errorf("SetBytes read %d bytes, expected 96", bytesRead)
	}
	return g1Point, nil
}

// parseEthereumScalarFromBytes parses a scalar from Ethereum format (32 bytes, big-endian)
func parseEthereumScalarFromBytes(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// convertG1AffineToCompressed converts a G1Affine point to compressed format (48 bytes)
func convertG1AffineToCompressed(point bls.G1Affine) []byte {
	uncompressed := point.Marshal()
	compressed := make([]byte, 48)
	copy(compressed, uncompressed[:48])
	compressed[0] |= 0x80 // Set compression flag
	yBytes := uncompressed[48:96]
	if isLexicographicallyLargestFp(yBytes) {
		compressed[0] |= 0x20 // Set y coordinate sort flag
	}
	return compressed
}

// convertG2AffineToCompressed converts a G2Affine point to compressed format (96 bytes)
func convertG2AffineToCompressed(point bls.G2Affine) []byte {
	uncompressed := point.Marshal()
	compressed := make([]byte, 96)
	copy(compressed, uncompressed[:96]) // Extract x coordinate (x.C1 + x.C0)
	compressed[0] |= 0x80               // Set compression flag
	yBytes := uncompressed[96:192]      // y coordinate (y.C1 + y.C0)
	if isLexicographicallyLargestFp2(yBytes) {
		compressed[0] |= 0x20 // Set y coordinate sort flag
	}
	return compressed
}

// parseEthereumG2PointFromBytes parses a G2 point from Ethereum format (256 bytes)
// Ethereum format: 64 bytes x.C1 (first 16 bytes are 0, last 48 bytes are big-endian) +
//
//	64 bytes x.C0 (first 16 bytes are 0, last 48 bytes are big-endian) +
//	64 bytes y.C1 (first 16 bytes are 0, last 48 bytes are big-endian) +
//	64 bytes y.C0 (first 16 bytes are 0, last 48 bytes are big-endian)
func parseEthereumG2PointFromBytes(data []byte) (bls.G2Affine, error) {
	if len(data) != 256 {
		return bls.G2Affine{}, fmt.Errorf("ethereum G2 point must be 256 bytes, got %d", len(data))
	}

	// Check that first 16 bytes of each field element are zero
	for i := 0; i < 16; i++ {
		if data[i] != 0 || data[64+i] != 0 || data[128+i] != 0 || data[192+i] != 0 {
			return bls.G2Affine{}, fmt.Errorf("non-zero padding bytes in Ethereum format")
		}
	}

	// Extract coordinates (last 48 bytes of each 64-byte field element, big-endian)
	// Neo's format: [x.C0 (64 bytes), x.C1 (64 bytes), y.C0 (64 bytes), y.C1 (64 bytes)]
	// Each 64-byte field: first 16 bytes are 0, last 48 bytes are the value
	xC0Bytes := data[16:64]   // x.C0 (48 bytes, big-endian) - first 64 bytes, skip first 16
	xC1Bytes := data[80:128]  // x.C1 (48 bytes, big-endian) - second 64 bytes, skip first 16
	yC0Bytes := data[144:192] // y.C0 (48 bytes, big-endian) - third 64 bytes, skip first 16
	yC1Bytes := data[208:256] // y.C1 (48 bytes, big-endian) - fourth 64 bytes, skip first 16

	// gnark-crypto SetBytes accepts uncompressed format (192 bytes)
	// Format: [x.C1 (48 bytes) + x.C0 (48 bytes) + y.C1 (48 bytes) + y.C0 (48 bytes)]
	// Note: gnark-crypto uses [C1, C0] order for Fp2, while Neo uses [C0, C1]
	// So we need to swap: gnark-crypto expects [C1, C0] but Neo provides [C0, C1]
	uncompressedPoint := append(append(append(xC1Bytes, xC0Bytes...), yC1Bytes...), yC0Bytes...)

	var g2Point bls.G2Affine
	bytesRead, err := g2Point.SetBytes(uncompressedPoint)
	if err != nil {
		return bls.G2Affine{}, fmt.Errorf("SetBytes failed: %v", err)
	}
	if bytesRead != 192 {
		return bls.G2Affine{}, fmt.Errorf("SetBytes read %d bytes, expected 192", bytesRead)
	}
	return g2Point, nil
}

// runEthereumVectorTest runs Ethereum test vector verification
// Note: Ethereum format is different from pairing_gen.go's computeMultiExpFromCompressed format
// - Ethereum: 160 bytes = 128 bytes point (uncompressed) + 32 bytes scalar
// - pairing_gen.go: compressed point (48 bytes) + scalar array
func runEthereumVectorTest() {
	fmt.Println("=== Ethereum BLS12-381 MultiExp Test Vector Verification ===")
	fmt.Println()
	fmt.Println("Note: Ethereum format uses uncompressed points (128 bytes),")
	fmt.Println("      while pairing_gen.go uses compressed format (48 bytes).")
	fmt.Println("      This test converts between formats.")
	fmt.Println()

	// Test Vector 1: Single G1 point + scalar
	// Ethereum format: 160 bytes = 128 bytes point + 32 bytes scalar
	ethG1SingleInputHex := "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000011"
	ethG1SingleExpectedHex := "000000000000000000000000000000001098f178f84fc753a76bb63709e9be91eec3ff5f7f3a5f4836f34fe8a1a6d6c5578d8fd820573cef3a01e2bfef3eaf3a000000000000000000000000000000000ea923110b733b531006075f796cc9368f2477fe26020f465468efbb380ce1f8eebaf5c770f31d320f9bd378dc758436"

	fmt.Println("Test 1: Single G1 point + scalar")
	input1, _ := hex.DecodeString(ethG1SingleInputHex)
	expected1, _ := hex.DecodeString(ethG1SingleExpectedHex)

	// Parse Ethereum format: 128 bytes point + 32 bytes scalar
	pointBytes := input1[0:128]
	scalarBytes := input1[128:160]

	// Parse point from Ethereum format
	g1Point, err := parseEthereumG1PointFromBytes(pointBytes)
	if err != nil {
		fmt.Printf("Error parsing Ethereum G1 point: %v\n", err)
		return
	}

	// Parse scalar from Ethereum format (big-endian)
	scalar := parseEthereumScalarFromBytes(scalarBytes)

	// Convert to compressed format for computeMultiExpFromCompressed
	g1Compressed := convertG1AffineToCompressed(g1Point)
	g1CompressedHex := hex.EncodeToString(g1Compressed)

	fmt.Printf("Point (Ethereum format, 128 bytes): %x\n", pointBytes)
	fmt.Printf("Point (compressed format, 48 bytes): %s\n", g1CompressedHex)
	fmt.Printf("Scalar: %s (0x%x)\n", scalar.String(), scalar)

	// Compute MultiExp using pairing_gen.go's computeMultiExpFromCompressed
	result, err := computeMultiExpFromCompressed(g1CompressedHex, []*big.Int{scalar}, false)
	if err != nil {
		fmt.Printf("Error computing MultiExp: %v\n", err)
		return
	}

	// Parse expected result from Ethereum format
	expectedPoint, err := parseEthereumG1PointFromBytes(expected1)
	if err != nil {
		fmt.Printf("Error parsing expected point: %v\n", err)
		return
	}
	expectedCompressed := convertG1AffineToCompressed(expectedPoint)
	expectedCompressedHex := hex.EncodeToString(expectedCompressed)

	fmt.Printf("\nResult (compressed):   %s\n", result)
	fmt.Printf("Expected (compressed):  %s\n", expectedCompressedHex)

	if result == expectedCompressedHex {
		fmt.Println("✅ Test 1 PASSED: Result matches Ethereum test vector!")
	} else {
		fmt.Println("❌ Test 1 FAILED: Result does not match Ethereum test vector!")
		fmt.Printf("Difference: result has %d chars, expected has %d chars\n", len(result), len(expectedCompressedHex))
		for i := 0; i < len(result) && i < len(expectedCompressedHex); i++ {
			if result[i] != expectedCompressedHex[i] {
				fmt.Printf("First difference at position %d: result='%c' (0x%02x), expected='%c' (0x%02x)\n",
					i, result[i], result[i], expectedCompressedHex[i], expectedCompressedHex[i])
				break
			}
		}
	}

	// Test Vector 2: Multiple G1 points + scalars
	fmt.Println("\n\nTest 2: Multiple G1 points + scalars")
	ethG1MultipleInputHex := "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000e12039459c60491672b6a6282355d8765ba6272387fb91a3e9604fa2a81450cf16b870bb446fc3a3e0a187fff6f89450000000000000000000000000000000018b6c1ed9f45d3cbc0b01b9d038dcecacbd702eb26469a0eb3905bd421461712f67f782b4735849644c1772c93fe3d09000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000147b327c8a15b39634a426af70c062b50632a744eddd41b5a4686414ef4cd9746bb11d0a53c6c2ff21bbcf331e07ac9200000000000000000000000000000000078c2e9782fa5d9ab4e728684382717aa2b8fad61b5f5e7cf3baa0bc9465f57342bb7c6d7b232e70eebcdbf70f903a450000000000000000000000000000000000000000000000000000000000000034"
	ethG1MultipleExpectedHex := "000000000000000000000000000000001339b4f51923efe38905f590ba2031a2e7154f0adb34a498dfde8fb0f1ccf6862ae5e3070967056385055a666f1b6fc70000000000000000000000000000000009fb423f7e7850ef9c4c11a119bb7161fe1d11ac5527051b29fe8f73ad4262c84c37b0f1b9f0e163a9682c22c7f98c80"

	input2, _ := hex.DecodeString(ethG1MultipleInputHex)
	expected2, _ := hex.DecodeString(ethG1MultipleExpectedHex)

	// Parse multiple pairs (each pair is 160 bytes: 128 bytes point + 32 bytes scalar)
	var points []bls.G1Affine
	var scalars []*big.Int

	for offset := 0; offset < len(input2); offset += 160 {
		pointBytes := input2[offset : offset+128]
		scalarBytes := input2[offset+128 : offset+160]

		point, err := parseEthereumG1PointFromBytes(pointBytes)
		if err != nil {
			fmt.Printf("Error parsing point at offset %d: %v\n", offset, err)
			return
		}
		scalar := parseEthereumScalarFromBytes(scalarBytes)

		points = append(points, point)
		scalars = append(scalars, scalar)

		compressed := convertG1AffineToCompressed(point)
		fmt.Printf("  Point %d (compressed): %x\n", len(points), compressed)
		fmt.Printf("  Scalar %d: %s (0x%x)\n", len(scalars), scalar.String(), scalar)
	}

	// Compute MultiExp: point1 × scalar1 + point2 × scalar2 + ...
	// Note: computeMultiExpFromCompressed only handles same point with different scalars
	// For different points, we need to compute manually
	var resultJac bls.G1Jac
	for i := 0; i < len(points); i++ {
		var g1Jac bls.G1Jac
		g1Jac.FromAffine(&points[i])
		var tempJac bls.G1Jac
		tempJac.ScalarMultiplication(&g1Jac, scalars[i])
		if i == 0 {
			resultJac.Set(&tempJac)
		} else {
			resultJac.AddAssign(&tempJac)
		}
	}
	var resultAffine bls.G1Affine
	resultAffine.FromJacobian(&resultJac)

	resultCompressed := convertG1AffineToCompressed(resultAffine)
	resultCompressedHex := hex.EncodeToString(resultCompressed)

	// Parse expected result
	expectedPoint2, err := parseEthereumG1PointFromBytes(expected2)
	if err != nil {
		fmt.Printf("Error parsing expected point: %v\n", err)
		return
	}
	expectedCompressed2 := convertG1AffineToCompressed(expectedPoint2)
	expectedCompressedHex2 := hex.EncodeToString(expectedCompressed2)

	fmt.Printf("\nResult (compressed):   %s\n", resultCompressedHex)
	fmt.Printf("Expected (compressed):  %s\n", expectedCompressedHex2)

	if resultCompressedHex == expectedCompressedHex2 {
		fmt.Println("✅ Test 2 PASSED: Result matches Ethereum test vector!")
	} else {
		fmt.Println("❌ Test 2 FAILED: Result does not match Ethereum test vector!")
		for i := 0; i < len(resultCompressedHex) && i < len(expectedCompressedHex2); i++ {
			if resultCompressedHex[i] != expectedCompressedHex2[i] {
				fmt.Printf("First difference at position %d: result='%c' (0x%02x), expected='%c' (0x%02x)\n",
					i, resultCompressedHex[i], resultCompressedHex[i], expectedCompressedHex2[i], expectedCompressedHex2[i])
				break
			}
		}
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ethereum-test" {
		runEthereumVectorTest()
		return
	}

	if len(os.Args) < 2 {
		// No arguments: run random mode with default max_scalars (G1)
		runRandomMode(128, false)
		return
	}

	// Check if first argument is "manual", "random", or "ethereum"
	mode := os.Args[1]
	if mode == "ethereum" {
		// Ethereum mode: parse flags
		ethereumFlags := flag.NewFlagSet("ethereum", flag.ExitOnError)
		inputHex := ethereumFlags.String("input", "", "Ethereum format input hex string")
		useG2 := ethereumFlags.Bool("use-g2", false, "Use G2 format (default: false, uses G1)")

		if err := ethereumFlags.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
			printUsage()
			os.Exit(1)
		}

		if *inputHex == "" {
			fmt.Fprintf(os.Stderr, "Error: --input is required\n")
			printUsage()
			os.Exit(1)
		}

		if err := runEthereumMode(*inputHex, *useG2); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if mode == "manual" {
		// Manual mode: parse flags
		manualFlags := flag.NewFlagSet("manual", flag.ExitOnError)
		g1Hex := manualFlags.String("g1", "", "Compressed G1 point (96 hex chars)")
		g2Hex := manualFlags.String("g2", "", "Compressed G2 point (192 hex chars)")
		scalarsStr := manualFlags.String("scalars", "", "Comma-separated list of scalar values")
		useG2 := manualFlags.Bool("use-g2", false, "Use G2 point (default: false, uses G1)")

		if err := manualFlags.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
			printUsage()
			os.Exit(1)
		}

		if *scalarsStr == "" {
			fmt.Fprintf(os.Stderr, "Error: --scalars is required\n")
			printUsage()
			os.Exit(1)
		}

		if err := runManualMode(*g1Hex, *g2Hex, *scalarsStr, *useG2); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if mode == "random" {
		// Random mode with optional max_scalars argument and --use-g2 flag
		randomFlags := flag.NewFlagSet("random", flag.ExitOnError)
		useG2 := randomFlags.Bool("use-g2", false, "Use G2 format (default: false, uses G1)")
		maxScalars := 128

		// Parse flags first
		if err := randomFlags.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
			printUsage()
			os.Exit(1)
		}

		// Check for max_scalars as positional argument
		if len(randomFlags.Args()) > 0 {
			arg, err := strconv.Atoi(randomFlags.Args()[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Invalid max_scalars '%s'. Must be a positive integer\n", randomFlags.Args()[0])
				printUsage()
				os.Exit(1)
			}
			if arg < 1 {
				fmt.Fprintf(os.Stderr, "Error: max_scalars must be at least 1, got: %d\n", arg)
				os.Exit(1)
			}
			maxScalars = arg
		}
		runRandomMode(maxScalars, *useG2)
	} else {
		// Try to parse as max_scalars (backward compatibility)
		// Check if there's a --use-g2 flag
		useG2 := false
		argsWithoutFlags := []string{}
		for _, arg := range os.Args[1:] {
			if arg == "--use-g2" {
				useG2 = true
			} else if !strings.HasPrefix(arg, "--") {
				argsWithoutFlags = append(argsWithoutFlags, arg)
			}
		}

		if len(argsWithoutFlags) > 0 {
			maxScalars, err := strconv.Atoi(argsWithoutFlags[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Unknown mode '%s'\n", mode)
				printUsage()
				os.Exit(1)
			}
			if maxScalars < 1 {
				fmt.Fprintf(os.Stderr, "Error: max_scalars must be at least 1, got: %d\n", maxScalars)
				os.Exit(1)
			}
			runRandomMode(maxScalars, useG2)
		} else {
			fmt.Fprintf(os.Stderr, "Error: Unknown mode '%s'\n", mode)
			printUsage()
			os.Exit(1)
		}
	}
}
