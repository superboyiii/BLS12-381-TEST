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

		// Use the helper function to ensure correct format
		g2ResultCompressed := convertG2AffineToCompressed(resultG2)
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
		// Use the helper function to ensure correct format
		g2Compressed := convertG2AffineToCompressed(Q)

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
				// Use the helper function to ensure correct format
				g2Compressed := convertG2AffineToCompressed(q)
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
			// Use the helper function to ensure correct format
			g2ResultCompressed := convertG2AffineToCompressed(resultG2)
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

	if uncompressedHex, err := compressedToUncompressedHex(result, useG2); err == nil {
		uncompressedBytes := 96
		if useG2 {
			uncompressedBytes = 192
		}
		fmt.Printf("MultiExp result (uncompressed, %d bytes = %d hex chars): %s\n", uncompressedBytes, uncompressedBytes*2, uncompressedHex)
	} else {
		fmt.Fprintf(os.Stderr, "Warning: unable to decode uncompressed result: %v\n", err)
	}
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
	fmt.Fprintf(os.Stderr, "  G1/G2 Add/Mul operations (Ethereum format):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go g1add --input <hex>\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go g2add --input <hex>\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go g1mul --input <hex>\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go g2mul --input <hex>\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go g2add-random  # Random G2 addition test\n")
	fmt.Fprintf(os.Stderr, "      - --input: Ethereum format input hex string\n")
	fmt.Fprintf(os.Stderr, "        g1add: 256 bytes (128 bytes point1 + 128 bytes point2)\n")
	fmt.Fprintf(os.Stderr, "        g2add: 512 bytes (256 bytes point1 + 256 bytes point2)\n")
	fmt.Fprintf(os.Stderr, "        g1mul: 160 bytes (128 bytes point + 32 bytes scalar)\n")
	fmt.Fprintf(os.Stderr, "        g2mul: 288 bytes (256 bytes point + 32 bytes scalar)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Pairing operation (Ethereum format):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go pairing --input <hex>\n")
	fmt.Fprintf(os.Stderr, "      - --input: Ethereum format input hex string\n")
	fmt.Fprintf(os.Stderr, "        Each pair: 384 bytes (128 bytes G1 + 256 bytes G2)\n")
	fmt.Fprintf(os.Stderr, "        Multiple pairs can be concatenated (must be multiple of 384 bytes)\n")
	fmt.Fprintf(os.Stderr, "        Result: 32 bytes, last byte is 1 if pairing product is identity, 0 otherwise\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Pairing random test mode (generates test scenarios):\n")
	fmt.Fprintf(os.Stderr, "    go run pairing_gen.go pairing-random\n")
	fmt.Fprintf(os.Stderr, "      - Generates random G1 and G2 points\n")
	fmt.Fprintf(os.Stderr, "      - Tests single pair: e(g1, g2)\n")
	fmt.Fprintf(os.Stderr, "      - Tests multiple pairs with bilinearity: e(g1, g2) * e(-g1, g2) = 1\n")
	fmt.Fprintf(os.Stderr, "      - Outputs C# array format for Bls12381MultiExpHelper.cs\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go 5\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go manual --g1 b2deb4e364cc09aceb924ebe236d28b5d180e27ee0428697f3d088b7c83637820c3c0c95b83189a6301dbaa405792564 --scalars \"1732363698,436226955,507793302,1540421097\"\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go ethereum --input 0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000011\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go g1add --input <256_bytes_hex>\n")
	fmt.Fprintf(os.Stderr, "  go run pairing_gen.go g1mul --input <160_bytes_hex>\n")
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

// encodeEthereumG1Point encodes a G1 point to Ethereum format (128 bytes)
// Format: 64 bytes x (first 16 bytes are 0, last 48 bytes are big-endian) +
//
//	64 bytes y (first 16 bytes are 0, last 48 bytes are big-endian)
func encodeEthereumG1Point(point bls.G1Affine) []byte {
	if point.IsInfinity() {
		return make([]byte, 128)
	}

	uncompressed := point.Marshal()
	if len(uncompressed) != 96 {
		panic(fmt.Sprintf("unexpected G1 uncompressed length: %d", len(uncompressed)))
	}

	// Extract x and y (48 bytes each, big-endian)
	xBytes := uncompressed[0:48]
	yBytes := uncompressed[48:96]

	// Ethereum format: 64 bytes per field element (first 16 bytes are 0, last 48 bytes are the value)
	output := make([]byte, 128)
	// Explicitly zero out padding bytes to ensure they are zero
	// x padding: bytes 0-15
	// y padding: bytes 64-79
	for i := 0; i < 16; i++ {
		output[i] = 0    // x padding
		output[64+i] = 0 // y padding
	}
	copy(output[16:64], xBytes)  // x: skip first 16 bytes, then 48 bytes
	copy(output[80:128], yBytes) // y: skip first 16 bytes, then 48 bytes

	return output
}

// encodeEthereumG2Point encodes a G2 point to Ethereum format (256 bytes)
// Format: 64 bytes x.C0 + 64 bytes x.C1 + 64 bytes y.C0 + 64 bytes y.C1
// Each 64-byte field: first 16 bytes are 0, last 48 bytes are big-endian
func encodeEthereumG2Point(point bls.G2Affine) []byte {
	if point.IsInfinity() {
		return make([]byte, 256)
	}

	uncompressed := point.Marshal()
	if len(uncompressed) != 192 {
		panic(fmt.Sprintf("unexpected G2 uncompressed length: %d", len(uncompressed)))
	}

	// gnark-crypto format: [x.C1 (48 bytes) + x.C0 (48 bytes) + y.C1 (48 bytes) + y.C0 (48 bytes)]
	// Ethereum format: [x.C0 (64 bytes) + x.C1 (64 bytes) + y.C0 (64 bytes) + y.C1 (64 bytes)]
	xC1Bytes := uncompressed[0:48]
	xC0Bytes := uncompressed[48:96]
	yC1Bytes := uncompressed[96:144]
	yC0Bytes := uncompressed[144:192]

	output := make([]byte, 256)
	// Explicitly zero out all padding bytes to ensure they are zero
	// Each 64-byte field has 16 bytes of padding at the start
	for i := 0; i < 16; i++ {
		output[i] = 0     // x.C0 padding: bytes 0-15
		output[64+i] = 0  // x.C1 padding: bytes 64-79
		output[128+i] = 0 // y.C0 padding: bytes 128-143
		output[192+i] = 0 // y.C1 padding: bytes 192-207
	}
	// x.C0: first 64 bytes, skip first 16, then 48 bytes
	copy(output[16:64], xC0Bytes)
	// x.C1: second 64 bytes, skip first 16, then 48 bytes
	copy(output[80:128], xC1Bytes)
	// y.C0: third 64 bytes, skip first 16, then 48 bytes
	copy(output[144:192], yC0Bytes)
	// y.C1: fourth 64 bytes, skip first 16, then 48 bytes
	copy(output[208:256], yC1Bytes)

	return output
}

// computeG1Add computes G1 point addition: p1 + p2
// Input: two Ethereum format G1 points (128 bytes each = 256 bytes total)
// Output: Ethereum format G1 point (128 bytes)
func computeG1Add(inputHex string) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}

	if len(inputBytes) != 256 {
		return "", fmt.Errorf("G1 add input must be 256 bytes (128 bytes per point), got %d", len(inputBytes))
	}

	// Parse two G1 points
	p1, err := parseEthereumG1PointFromBytes(inputBytes[0:128])
	if err != nil {
		return "", fmt.Errorf("failed to parse first G1 point: %v", err)
	}

	p2, err := parseEthereumG1PointFromBytes(inputBytes[128:256])
	if err != nil {
		return "", fmt.Errorf("failed to parse second G1 point: %v", err)
	}

	// Compute addition: p1 + p2
	var p1Jac bls.G1Jac
	p1Jac.FromAffine(&p1)
	var p2Jac bls.G1Jac
	p2Jac.FromAffine(&p2)
	p1Jac.AddAssign(&p2Jac)

	var result bls.G1Affine
	result.FromJacobian(&p1Jac)

	// Encode result to Ethereum format
	resultBytes := encodeEthereumG1Point(result)
	return hex.EncodeToString(resultBytes), nil
}

// computeG2Add computes G2 point addition: p1 + p2
// Input: two Ethereum format G2 points (256 bytes each = 512 bytes total)
// Output: Ethereum format G2 point (256 bytes)
// This function follows gnark-crypto standard and is compatible with Bls12381MultiExpHelper.cs
func computeG2Add(inputHex string) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}

	if len(inputBytes) != 512 {
		return "", fmt.Errorf("G2 add input must be 512 bytes (256 bytes per point), got %d", len(inputBytes))
	}

	// Parse two G2 points from Ethereum format
	// Create separate slices to avoid potential slice sharing issues
	point1Data := make([]byte, 256)
	copy(point1Data, inputBytes[0:256])
	point2Data := make([]byte, 256)
	copy(point2Data, inputBytes[256:512])

	// Verify point2Data's x.C0 padding is zero before parsing
	for i := 0; i < 16; i++ {
		if point2Data[i] != 0 {
			return "", fmt.Errorf("second point x.C0 padding byte[%d] is non-zero: 0x%02x. Input data may be corrupted. First point y.C0 data (bytes 144-160): %x", i, point2Data[i], inputBytes[144:160])
		}
	}

	p1, err := parseEthereumG2PointFromBytes(point1Data)
	if err != nil {
		return "", fmt.Errorf("failed to parse first G2 point: %v", err)
	}

	p2, err := parseEthereumG2PointFromBytes(point2Data)
	if err != nil {
		return "", fmt.Errorf("failed to parse second G2 point: %v", err)
	}

	// Compute addition: p1 + p2 using gnark-crypto standard API
	// Convert to Jacobian coordinates for efficient addition
	var p1Jac bls.G2Jac
	p1Jac.FromAffine(&p1)
	var p2Jac bls.G2Jac
	p2Jac.FromAffine(&p2)

	// Perform addition: p1Jac = p1Jac + p2Jac
	p1Jac.AddAssign(&p2Jac)

	// Convert back to Affine coordinates
	var result bls.G2Affine
	result.FromJacobian(&p1Jac)

	// Encode result to Ethereum format
	resultBytes := encodeEthereumG2Point(result)
	return hex.EncodeToString(resultBytes), nil
}

// runPairingRandomMode runs the random pairing mode
// This generates random G1 and G2 points, and can test multiple pairing scenarios:
// - Single pair: e(g1, g2)
// - Multiple pairs with bilinearity: e(g1, g2) * e(-g1, g2) = 1
// This matches Neo's TestBls12PairingAliasMultiplePairs test scenario
func runPairingRandomMode() {
	fmt.Println("=== BLS12-381 Pairing Random Test Mode ===")
	fmt.Println("Generating random G1 and G2 points for pairing test...")
	fmt.Println()

	// Generate random G1 and G2 points
	P, err := randomOnG1()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G1 point: %v", err))
	}

	Q, err := bls.RandomOnG2()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G2 point: %v", err))
	}

	// Convert to compressed format for output
	g1Compressed := convertG1AffineToCompressed(P)
	g2Compressed := convertG2AffineToCompressed(Q)

	fmt.Println("Generated Points (compressed format):")
	fmt.Printf("G1 (compressed, 48 bytes, 96 hex chars): %x\n", g1Compressed)
	fmt.Printf("G2 (compressed, 96 bytes, 192 hex chars): %x\n", g2Compressed)
	fmt.Println()

	// Test Scenario 1: Single pair e(g1, g2)
	fmt.Println("=== Test Scenario 1: Single Pair ===")
	fmt.Println("Computing: e(g1, g2)")
	singlePairResult, err := bls.Pair([]bls.G1Affine{P}, []bls.G2Affine{Q})
	if err != nil {
		panic(fmt.Sprintf("pairing failed: %v", err))
	}
	var identity bls.GT
	identity.SetOne()
	isIdentity1 := singlePairResult.Equal(&identity)
	fmt.Printf("Result is identity: %v\n", isIdentity1)
	fmt.Printf("Pairing result (GT element): %x\n", singlePairResult.Marshal())
	fmt.Println()

	// Test Scenario 2: Multiple pairs with bilinearity e(g1, g2) * e(-g1, g2) = 1
	fmt.Println("=== Test Scenario 2: Multiple Pairs (Bilinearity Test) ===")
	fmt.Println("Computing: e(g1, g2) * e(-g1, g2)")

	// Compute -g1 (negation)
	var negP bls.G1Affine
	negP.Neg(&P)

	// Compute first pairing: e(g1, g2)
	pair1, err := bls.Pair([]bls.G1Affine{P}, []bls.G2Affine{Q})
	if err != nil {
		panic(fmt.Sprintf("first pairing failed: %v", err))
	}

	// Compute second pairing: e(-g1, g2)
	pair2, err := bls.Pair([]bls.G1Affine{negP}, []bls.G2Affine{Q})
	if err != nil {
		panic(fmt.Sprintf("second pairing failed: %v", err))
	}

	// Multiply: pair1 * pair2 = e(g1, g2) * e(-g1, g2)
	var product bls.GT
	product.SetOne()
	product.Mul(&product, &pair1)
	product.Mul(&product, &pair2)

	isIdentity2 := product.Equal(&identity)
	fmt.Printf("Result is identity: %v (expected: true)\n", isIdentity2)
	if isIdentity2 {
		fmt.Println("✅ Bilinearity test PASSED: e(g1, g2) * e(-g1, g2) = 1")
	} else {
		fmt.Println("❌ Bilinearity test FAILED: e(g1, g2) * e(-g1, g2) ≠ 1")
	}
	fmt.Println()

	// Encode points to Ethereum format for Neo compatibility
	g1Ethereum := encodeEthereumG1Point(P)
	negG1Ethereum := encodeEthereumG1Point(negP)
	g2Ethereum := encodeEthereumG2Point(Q)

	// Build input for multiple pairs: [g1, g2] + [-g1, g2]
	const pairLength = 128 + 256 // 384 bytes
	multiplePairsInput := make([]byte, pairLength*2)
	copy(multiplePairsInput[0:128], g1Ethereum)
	copy(multiplePairsInput[128:384], g2Ethereum)
	copy(multiplePairsInput[384:512], negG1Ethereum)
	copy(multiplePairsInput[512:768], g2Ethereum)

	fmt.Println("=== Ethereum Format Input (for Neo Bls12Pairing) ===")
	fmt.Println("Multiple pairs input (768 bytes = 1536 hex chars):")
	fmt.Printf("  Pair 1: G1 (128 bytes) + G2 (256 bytes)\n")
	fmt.Printf("  Pair 2: -G1 (128 bytes) + G2 (256 bytes)\n")
	fmt.Printf("Input hex: %x\n", multiplePairsInput)
	fmt.Println()

	// Compute using computePairing to verify
	inputHex := hex.EncodeToString(multiplePairsInput)
	result, err := computePairing(inputHex)
	if err != nil {
		panic(fmt.Sprintf("computePairing failed: %v", err))
	}

	fmt.Println("=== Expected Result (from computePairing) ===")
	fmt.Printf("Result (32 bytes, 64 hex chars): %s\n", result)
	fmt.Printf("Last byte: 0x%02x (1 = identity, 0 = non-identity)\n", result[len(result)-2:])
	if result[len(result)-2:] == "01" {
		fmt.Println("✅ Result correctly identifies as identity!")
	} else {
		fmt.Println("❌ Result incorrectly identified as non-identity!")
	}
	fmt.Println()

	// Output C# array format for Bls12381MultiExpHelper.cs
	fmt.Println("=== C# Array Format (copy to Bls12381MultiExpHelper.cs) ===")
	fmt.Println("// For pairing with multiple pairs (bilinearity test)")
	fmt.Println("// This tests: e(g1, g2) * e(-g1, g2) = 1")
	fmt.Print("private static readonly string[] G1_PAIRS = new string[]\n{\n")
	fmt.Printf("    \"%x\",  // Pair 0: G1 point\n", g1Compressed)
	fmt.Printf("    \"%x\"   // Pair 1: -G1 point (negation)\n", convertG1AffineToCompressed(negP))
	fmt.Println("};")
	fmt.Println()
	fmt.Print("private static readonly string[] G2_PAIRS = new string[]\n{\n")
	fmt.Printf("    \"%x\",  // Pair 0: G2 point\n", g2Compressed)
	fmt.Printf("    \"%x\"   // Pair 1: G2 point (same as pair 0)\n", g2Compressed)
	fmt.Println("};")
	fmt.Println()
	fmt.Println("// Expected result: 32 bytes, last byte = 0x01 (identity)")
	fmt.Printf("// Expected result hex: %s\n", result)
	fmt.Println()
	fmt.Println("// Note: This matches Neo's TestBls12PairingAliasMultiplePairs test scenario")
	fmt.Println("//       e(g1, g2) * e(-g1, g2) = e(g1, g2) * e(g1, g2)^(-1) = 1")
}

// runG2AddRandomMode runs the random G2 addition mode
// This generates two random G2 points, adds them, and outputs the result
// This function follows gnark-crypto standard and is compatible with Bls12381MultiExpHelper.cs
func runG2AddRandomMode() {
	fmt.Println("=== G2 Addition Random Test Mode ===")
	fmt.Println("Generating two random G2 points and computing their sum...")
	fmt.Println()

	// Generate two random G2 points using gnark-crypto standard API
	Q1, err := bls.RandomOnG2()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G2 point 1: %v", err))
	}

	Q2, err := bls.RandomOnG2()
	if err != nil {
		panic(fmt.Sprintf("failed to generate random G2 point 2: %v", err))
	}

	// Encode both points to Ethereum format
	point1Ethereum := encodeEthereumG2Point(Q1)
	point2Ethereum := encodeEthereumG2Point(Q2)

	// Concatenate: point1 (256 bytes) + point2 (256 bytes) = 512 bytes
	inputBytes := make([]byte, 512)

	// Verify point lengths before copying
	if len(point1Ethereum) != 256 {
		panic(fmt.Sprintf("point1Ethereum has invalid length: %d (expected 256)", len(point1Ethereum)))
	}
	if len(point2Ethereum) != 256 {
		panic(fmt.Sprintf("point2Ethereum has invalid length: %d (expected 256)", len(point2Ethereum)))
	}

	// Copy points to inputBytes
	copy(inputBytes[0:256], point1Ethereum)
	copy(inputBytes[256:512], point2Ethereum)

	// Verify the concatenation is correct
	// Check that second point's x.C0 padding (bytes 256-272) is all zeros
	for i := 256; i < 272; i++ {
		if inputBytes[i] != 0 {
			panic(fmt.Sprintf("Second point x.C0 padding byte[%d] is non-zero: 0x%02x. This indicates a bug in data concatenation.", i, inputBytes[i]))
		}
	}

	inputHex := hex.EncodeToString(inputBytes)

	// Output point information
	fmt.Println("Point 1 (compressed):")
	g2Compressed1 := convertG2AffineToCompressed(Q1)
	fmt.Printf("  %x\n", g2Compressed1)
	fmt.Println("Point 1 (Ethereum format, first 64 bytes of x.C0):")
	fmt.Printf("  %x...\n", point1Ethereum[0:64])

	fmt.Println()
	fmt.Println("Point 2 (compressed):")
	g2Compressed2 := convertG2AffineToCompressed(Q2)
	fmt.Printf("  %x\n", g2Compressed2)
	fmt.Println("Point 2 (Ethereum format, first 64 bytes of x.C0):")
	fmt.Printf("  %x...\n", point2Ethereum[0:64])

	fmt.Println()
	fmt.Println("=== Computing G2 Addition ===")
	fmt.Printf("Input (Ethereum format, 512 bytes = 1024 hex chars):\n")
	fmt.Printf("  First 128 hex chars: %s...\n", inputHex[0:128])
	fmt.Printf("  Last 128 hex chars: ...%s\n", inputHex[len(inputHex)-128:])

	// Compute addition using computeG2Add
	resultHex, err := computeG2Add(inputHex)
	if err != nil {
		panic(fmt.Sprintf("failed to compute G2 addition: %v", err))
	}

	fmt.Println()
	fmt.Println("=== Result ===")
	fmt.Printf("Result (Ethereum format, 256 bytes = 512 hex chars):\n")
	fmt.Printf("  %s\n", resultHex)

	// Verify: Compute expected result using gnark-crypto directly
	fmt.Println()
	fmt.Println("=== Verification ===")
	var Q1Jac bls.G2Jac
	Q1Jac.FromAffine(&Q1)
	var Q2Jac bls.G2Jac
	Q2Jac.FromAffine(&Q2)
	Q1Jac.AddAssign(&Q2Jac)
	var expectedResult bls.G2Affine
	expectedResult.FromJacobian(&Q1Jac)

	expectedEthereum := encodeEthereumG2Point(expectedResult)
	expectedHex := hex.EncodeToString(expectedEthereum)

	fmt.Printf("Expected (Ethereum format):\n")
	fmt.Printf("  %s\n", expectedHex)

	if resultHex == expectedHex {
		fmt.Println("✅ Verification PASSED: Result matches expected value!")
	} else {
		fmt.Println("❌ Verification FAILED: Result does not match expected value!")
		fmt.Printf("Difference: result has %d chars, expected has %d chars\n", len(resultHex), len(expectedHex))
		for i := 0; i < len(resultHex) && i < len(expectedHex); i++ {
			if resultHex[i] != expectedHex[i] {
				fmt.Printf("First difference at position %d: result='%c' (0x%02x), expected='%c' (0x%02x)\n",
					i, resultHex[i], resultHex[i], expectedHex[i], expectedHex[i])
				break
			}
		}
	}

	fmt.Println()
	fmt.Println("=== C# Test Input Format ===")
	fmt.Println("You can use this input to test with C# helper:")
	fmt.Printf("Point 1 (compressed, 192 hex chars):\n")
	fmt.Printf("  %x\n", g2Compressed1)
	fmt.Printf("Point 2 (compressed, 192 hex chars):\n")
	fmt.Printf("  %x\n", g2Compressed2)
	fmt.Printf("Ethereum format input (1024 hex chars):\n")
	fmt.Printf("  %s\n", inputHex)
}

// computeG1Mul computes G1 point multiplication: point * scalar
// Input: Ethereum format G1 point (128 bytes) + scalar (32 bytes) = 160 bytes total
// Output: Ethereum format G1 point (128 bytes)
func computeG1Mul(inputHex string) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}

	if len(inputBytes) != 160 {
		return "", fmt.Errorf("G1 mul input must be 160 bytes (128 bytes point + 32 bytes scalar), got %d", len(inputBytes))
	}

	// Parse G1 point and scalar
	point, err := parseEthereumG1PointFromBytes(inputBytes[0:128])
	if err != nil {
		return "", fmt.Errorf("failed to parse G1 point: %v", err)
	}

	scalar := parseEthereumScalarFromBytes(inputBytes[128:160])

	// Compute multiplication: point * scalar
	var pointJac bls.G1Jac
	pointJac.FromAffine(&point)
	pointJac.ScalarMultiplication(&pointJac, scalar)

	var result bls.G1Affine
	result.FromJacobian(&pointJac)

	// Encode result to Ethereum format
	resultBytes := encodeEthereumG1Point(result)
	return hex.EncodeToString(resultBytes), nil
}

// computeG2Mul computes G2 point multiplication: point * scalar
// Input: Ethereum format G2 point (256 bytes) + scalar (32 bytes) = 288 bytes total
// Output: Ethereum format G2 point (256 bytes)
func computeG2Mul(inputHex string) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}

	if len(inputBytes) != 288 {
		return "", fmt.Errorf("G2 mul input must be 288 bytes (256 bytes point + 32 bytes scalar), got %d", len(inputBytes))
	}

	// Parse G2 point and scalar
	point, err := parseEthereumG2PointFromBytes(inputBytes[0:256])
	if err != nil {
		return "", fmt.Errorf("failed to parse G2 point: %v", err)
	}

	scalar := parseEthereumScalarFromBytes(inputBytes[256:288])

	// Compute multiplication: point * scalar
	var pointJac bls.G2Jac
	pointJac.FromAffine(&point)
	pointJac.ScalarMultiplication(&pointJac, scalar)

	var result bls.G2Affine
	result.FromJacobian(&pointJac)

	// Encode result to Ethereum format
	resultBytes := encodeEthereumG2Point(result)
	return hex.EncodeToString(resultBytes), nil
}

// computePairing computes BLS12-381 pairing: e(g1_1, g2_1) * e(g1_2, g2_2) * ...
// Input: Ethereum format pairs, each pair is G1 (128 bytes) + G2 (256 bytes) = 384 bytes
// Output: 32 bytes, last byte is 1 if pairing result is identity (unit element), 0 otherwise
// This matches Neo's Bls12Pairing implementation
func computePairing(inputHex string) (string, error) {
	inputHex = strings.TrimSpace(inputHex)
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse input hex: %v", err)
	}
	// Create a copy to avoid any potential modifications by gnark-crypto
	inputBytesCopy := make([]byte, len(inputBytes))
	copy(inputBytesCopy, inputBytes)
	inputBytes = inputBytesCopy

	// Each pair is 384 bytes: 128 bytes G1 + 256 bytes G2
	const pairLength = 128 + 256 // 384 bytes
	if len(inputBytes) == 0 {
		// Empty input: return identity (unit element) = 1
		result := make([]byte, 32)
		result[31] = 1
		return hex.EncodeToString(result), nil
	}

	if len(inputBytes)%pairLength != 0 {
		return "", fmt.Errorf("pairing input must be multiple of %d bytes (each pair is %d bytes), got %d", pairLength, pairLength, len(inputBytes))
	}

	// Parse all pairs and compute pairing product
	var accumulator bls.GT
	accumulator.SetOne() // Start with identity element

	numPairs := len(inputBytes) / pairLength
	for i := 0; i < numPairs; i++ {
		offset := i * pairLength
		g1Bytes := inputBytes[offset : offset+128]
		g2Bytes := inputBytes[offset+128 : offset+pairLength]

		// Create copies to avoid any potential modifications to inputBytes by gnark-crypto
		g1BytesCopy := make([]byte, len(g1Bytes))
		copy(g1BytesCopy, g1Bytes)
		g2BytesCopy := make([]byte, len(g2Bytes))
		copy(g2BytesCopy, g2Bytes)

		// Parse G1 point from Ethereum format (using copy)
		g1Point, err := parseEthereumG1PointFromBytes(g1BytesCopy)
		if err != nil {
			return "", fmt.Errorf("failed to parse G1 point at pair %d: %v", i, err)
		}

		// Parse G2 point from Ethereum format (using copy)
		g2Point, err := parseEthereumG2PointFromBytes(g2BytesCopy)
		if err != nil {
			return "", fmt.Errorf("failed to parse G2 point at pair %d: %v", i, err)
		}

		// Compute pairing: e(g1, g2)
		pairResult, err := bls.Pair([]bls.G1Affine{g1Point}, []bls.G2Affine{g2Point})
		if err != nil {
			return "", fmt.Errorf("failed to compute pairing at pair %d: %v", i, err)
		}

		// Multiply accumulator by pair result: accumulator = accumulator * pairResult
		accumulator.Mul(&accumulator, &pairResult)
	}

	// Check if result is identity (unit element)
	// In gnark-crypto, GT.Identity() is the unit element
	// We check if accumulator == 1 (identity)
	var identity bls.GT
	identity.SetOne()
	isIdentity := accumulator.Equal(&identity)

	// Encode result: 32 bytes, last byte is 1 if identity, 0 otherwise
	result := make([]byte, 32)
	if isIdentity {
		result[31] = 1
	} else {
		result[31] = 0
	}

	return hex.EncodeToString(result), nil
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

// compressedToUncompressedHex converts a compressed point hex string back to the
// uncompressed hex form (96 bytes for G1, 192 bytes for G2) for display.
func compressedToUncompressedHex(compressedHex string, useG2 bool) (string, error) {
	bytes, err := hex.DecodeString(strings.TrimSpace(compressedHex))
	if err != nil {
		return "", fmt.Errorf("invalid compressed hex: %w", err)
	}

	if useG2 {
		if len(bytes) != 96 {
			return "", fmt.Errorf("compressed G2 value must be 96 bytes, got %d", len(bytes))
		}
		var point bls.G2Affine
		if _, err := point.SetBytes(bytes); err != nil {
			return "", fmt.Errorf("failed to parse compressed G2: %w", err)
		}
		return hex.EncodeToString(point.Marshal()), nil
	}

	if len(bytes) != 48 {
		return "", fmt.Errorf("compressed G1 value must be 48 bytes, got %d", len(bytes))
	}
	var point bls.G1Affine
	if _, err := point.SetBytes(bytes); err != nil {
		return "", fmt.Errorf("failed to parse compressed G1: %w", err)
	}
	return hex.EncodeToString(point.Marshal()), nil
}

// convertG2AffineToCompressed converts a G2Affine point to compressed format (96 bytes)
// Format matches Neo's G2Affine.ToCompressed():
// - First 48 bytes: x.C1
// - Next 48 bytes: x.C0
// - First byte flags: 0x80 (compression), 0x40 (infinity), 0x20 (sort)
// The flags are stored in the upper 3 bits of the first byte, while the lower 5 bits
// are part of the x.C1 coordinate data.
func convertG2AffineToCompressed(point bls.G2Affine) []byte {
	uncompressed := point.Marshal()
	compressed := make([]byte, 96)

	// Extract x coordinate: gnark-crypto format is [x.C1 (48) + x.C0 (48) + y.C1 (48) + y.C0 (48)]
	// Neo format is [x.C1 (48) + x.C0 (48)]
	copy(compressed, uncompressed[:96]) // Extract x coordinate (x.C1 + x.C0)

	// Clear only the flag bits (0x80, 0x40, 0x20) from the first byte before setting them
	// The lower 5 bits (0x1F) are part of the x.C1 coordinate data and must be preserved
	// Note: We use & 0x1F to clear the upper 3 bits (flags) while preserving the lower 5 bits (data)
	compressed[0] &= 0x1F

	// Set compression flag (MSB) - always set for compressed format
	compressed[0] |= 0x80

	// Check if point is at infinity
	if point.IsInfinity() {
		compressed[0] |= 0x40 // Set infinity flag
		// For infinity point, Neo's validation requires: infinity -> !sort_flag & x.IsZero
		// The sort flag should NOT be set for infinity points
		return compressed
	}

	// Extract y coordinate to determine sort flag
	yBytes := uncompressed[96:192] // y coordinate (y.C1 + y.C0)
	if isLexicographicallyLargestFp2(yBytes) {
		compressed[0] |= 0x20 // Set y coordinate sort flag
	}

	return compressed
}

// parseEthereumG2PointFromBytes parses a G2 point from Ethereum format (256 bytes)
// Ethereum format: 64 bytes x.C0 (first 16 bytes are 0, last 48 bytes are big-endian) +
//
//	64 bytes x.C1 (first 16 bytes are 0, last 48 bytes are big-endian) +
//	64 bytes y.C0 (first 16 bytes are 0, last 48 bytes are big-endian) +
//	64 bytes y.C1 (first 16 bytes are 0, last 48 bytes are big-endian)
//
// This matches Neo's EncodeEthereumG2 format: [x.C0, x.C1, y.C0, y.C1]
func parseEthereumG2PointFromBytes(data []byte) (bls.G2Affine, error) {
	if len(data) != 256 {
		return bls.G2Affine{}, fmt.Errorf("ethereum G2 point must be 256 bytes, got %d", len(data))
	}

	// Debug: Check what data we actually received
	fmt.Fprintf(os.Stderr, "Debug: parseEthereumG2PointFromBytes received data:\n")
	fmt.Fprintf(os.Stderr, "  x.C0 padding (bytes 0-16): %x\n", data[0:16])
	fmt.Fprintf(os.Stderr, "  x.C0 data (bytes 16-64): %x\n", data[16:64])
	fmt.Fprintf(os.Stderr, "  x.C1 padding (bytes 64-80): %x\n", data[64:80])
	fmt.Fprintf(os.Stderr, "  x.C1 data (bytes 80-128): %x\n", data[80:128])
	fmt.Fprintf(os.Stderr, "  y.C0 padding (bytes 128-144): %x\n", data[128:144])
	fmt.Fprintf(os.Stderr, "  y.C0 data (bytes 144-192): %x\n", data[144:192])
	fmt.Fprintf(os.Stderr, "  y.C1 padding (bytes 192-208): %x\n", data[192:208])
	fmt.Fprintf(os.Stderr, "  y.C1 data (bytes 208-256): %x\n", data[208:256])

	// Check that first 16 bytes of each field element are zero
	// Ethereum format: each 64-byte field element has 16 bytes of padding (zeros) followed by 48 bytes of data
	// Note: We'll warn about non-zero padding but continue, as the actual data is in the last 48 bytes
	hasNonZeroPadding := false
	var paddingErrors []string
	for i := 0; i < 16; i++ {
		if data[i] != 0 {
			hasNonZeroPadding = true
			paddingErrors = append(paddingErrors, fmt.Sprintf("x.C0[%d]=0x%02x", i, data[i]))
		}
		if data[64+i] != 0 {
			hasNonZeroPadding = true
			paddingErrors = append(paddingErrors, fmt.Sprintf("x.C1[%d]=0x%02x", 64+i, data[64+i]))
		}
		if data[128+i] != 0 {
			hasNonZeroPadding = true
			paddingErrors = append(paddingErrors, fmt.Sprintf("y.C0[%d]=0x%02x", 128+i, data[128+i]))
		}
		if data[192+i] != 0 {
			hasNonZeroPadding = true
			paddingErrors = append(paddingErrors, fmt.Sprintf("y.C1[%d]=0x%02x", 192+i, data[192+i]))
		}
	}
	if hasNonZeroPadding {
		// Log warning but continue - the actual coordinate data is in the last 48 bytes of each field
		fmt.Fprintf(os.Stderr, "Warning: non-zero padding bytes in Ethereum format G2 point: %v\n", paddingErrors)
		fmt.Fprintf(os.Stderr, "  Continuing anyway - coordinate data is in bytes [16:64], [80:128], [144:192], [208:256]\n")
	}

	// Extract coordinates (last 48 bytes of each 64-byte field element, big-endian)
	// Ethereum/Neo format: [x.C0 (64 bytes), x.C1 (64 bytes), y.C0 (64 bytes), y.C1 (64 bytes)]
	// Each 64-byte field: first 16 bytes are 0, last 48 bytes are the value
	// However, if padding bytes are non-zero, the data might be in a different location
	// Let's try both: standard location and alternative location (if padding is non-zero)

	// Standard extraction (assuming padding is correct)
	xC0Bytes := data[16:64]   // x.C0 (48 bytes, big-endian) - first 64 bytes, skip first 16
	xC1Bytes := data[80:128]  // x.C1 (48 bytes, big-endian) - second 64 bytes, skip first 16
	yC0Bytes := data[144:192] // y.C0 (48 bytes, big-endian) - third 64 bytes, skip first 16
	yC1Bytes := data[208:256] // y.C1 (48 bytes, big-endian) - fourth 64 bytes, skip first 16

	// If padding is non-zero, the data might actually be in the first 48 bytes of each field
	// Let's check if the standard extraction produces valid data, and if not, try alternative
	if hasNonZeroPadding {
		fmt.Fprintf(os.Stderr, "  Attempting to extract coordinates from standard location [16:64], [80:128], [144:192], [208:256]\n")
		// If this fails, we might need to try alternative locations
	}

	// gnark-crypto's G2Affine.SetBytes only supports compressed format (96 bytes), not uncompressed (192 bytes)
	// We need to convert Ethereum format to compressed format first
	// Compressed format: [x.C1 (48 bytes) + x.C0 (48 bytes)] with flags in first byte
	// This matches the approach used in computeMultiExpFromCompressed for G2 points

	// Construct compressed format from x coordinate
	// Format: [xC1, xC0] (96 bytes total)
	compressed := make([]byte, 96)
	copy(compressed[0:48], xC1Bytes)  // x.C1 (first 48 bytes)
	copy(compressed[48:96], xC0Bytes) // x.C0 (next 48 bytes)

	// Clear flag bits (upper 3 bits) while preserving lower 5 bits of first byte
	// The lower 5 bits are part of the x.C1 coordinate data
	compressed[0] &= 0x1F

	// Set compression flag (MSB) - always set for compressed format
	compressed[0] |= 0x80

	// Determine sort flag based on y coordinate
	// y coordinate format: [y.C1, y.C0] (96 bytes, big-endian)
	yBytes := append(yC1Bytes, yC0Bytes...)
	if isLexicographicallyLargestFp2(yBytes) {
		compressed[0] |= 0x20 // Set y coordinate sort flag
	}

	// Parse compressed format using SetBytes (same as computeMultiExpFromCompressed)
	// Debug: Show compressed format before parsing
	fmt.Fprintf(os.Stderr, "Debug: Constructed compressed format (first 16 bytes): %x\n", compressed[0:16])
	fmt.Fprintf(os.Stderr, "Debug: xC1Bytes (first 16 bytes): %x\n", xC1Bytes[0:16])
	fmt.Fprintf(os.Stderr, "Debug: xC0Bytes (first 16 bytes): %x\n", xC0Bytes[0:16])

	var g2Point bls.G2Affine
	bytesRead, err := g2Point.SetBytes(compressed)
	if err != nil {
		// If padding was non-zero and parsing failed, try alternative location
		// Data might be in compact format [0:48], [48:96], [96:144], [144:192] instead of Ethereum format [16:64], [80:128], [144:192], [208:256]
		if hasNonZeroPadding {
			fmt.Fprintf(os.Stderr, "  Standard location failed, trying alternative location [0:48], [48:96], [96:144], [144:192] (compact format)\n")

			// Try multiple alternative formats
			// Format 1: Compact format [0:48], [48:96], [96:144], [144:192]
			xC0BytesAlt1 := data[0:48]
			xC1BytesAlt1 := data[48:96]
			yC0BytesAlt1 := data[96:144]
			yC1BytesAlt1 := data[144:192]

			// Format 2: If padding bytes contain actual data, the format might be wrong
			// Try using the padding bytes themselves as part of the coordinate data
			// This is a last resort - if padding bytes are non-zero, maybe they ARE the data
			// Format: Use first 16 bytes (padding) + next 32 bytes for x.C0, etc.
			// Actually, let's try a different approach: maybe data is shifted
			// Format 2: [16:64] for x.C0 (standard), but [0:48] for x.C1 (if padding is wrong)
			// Or maybe the entire format is different - let's try using padding bytes as coordinate data
			// Format 2: If padding bytes are non-zero, maybe data is shifted
			// Try: x.C0 from [0:48] (including padding), x.C1 from [64:112], y.C0 from [128:176], y.C1 from [192:240]
			// This assumes data might be in a mixed format where some fields use padding bytes
			xC0BytesAlt2 := data[0:48]    // First 48 bytes (including padding)
			xC1BytesAlt2 := data[64:112]  // Second field, first 48 bytes (skip padding)
			yC0BytesAlt2 := data[128:176] // Third field, first 48 bytes (skip padding)
			yC1BytesAlt2 := data[192:240] // Fourth field, first 48 bytes (skip padding)

			// Try Format 1 first (compact)
			xC0BytesAlt := xC0BytesAlt1
			xC1BytesAlt := xC1BytesAlt1
			yC0BytesAlt := yC0BytesAlt1
			yC1BytesAlt := yC1BytesAlt1

			// Construct compressed format from alternative location
			compressedAlt := make([]byte, 96)
			copy(compressedAlt[0:48], xC1BytesAlt)  // x.C1 (first 48 bytes)
			copy(compressedAlt[48:96], xC0BytesAlt) // x.C0 (next 48 bytes)

			// Clear flag bits and set compression flag
			compressedAlt[0] &= 0x1F
			compressedAlt[0] |= 0x80

			// Determine sort flag based on y coordinate
			yBytesAlt := append(yC1BytesAlt, yC0BytesAlt...)
			if isLexicographicallyLargestFp2(yBytesAlt) {
				compressedAlt[0] |= 0x20
			}

			// Try parsing with Format 1 (compact)
			fmt.Fprintf(os.Stderr, "    Trying Format 1 (compact): [0:48], [48:96], [96:144], [144:192]\n")
			bytesReadAlt, errAlt := g2Point.SetBytes(compressedAlt)
			if errAlt != nil {
				// Try Format 2
				fmt.Fprintf(os.Stderr, "    Format 1 failed (%v), trying Format 2 (padding bytes included)\n", errAlt)
				compressedAlt2 := make([]byte, 96)
				copy(compressedAlt2[0:48], xC1BytesAlt2[0:48])
				copy(compressedAlt2[48:96], xC0BytesAlt2[0:48])
				compressedAlt2[0] &= 0x1F
				compressedAlt2[0] |= 0x80
				yBytesAlt2 := append(yC1BytesAlt2[0:48], yC0BytesAlt2[0:48]...)
				if isLexicographicallyLargestFp2(yBytesAlt2) {
					compressedAlt2[0] |= 0x20
				}

				bytesReadAlt2, errAlt2 := g2Point.SetBytes(compressedAlt2)
				if errAlt2 != nil {
					return bls.G2Affine{}, fmt.Errorf("failed to parse G2 point from compressed format (tried standard and 2 alternative formats): "+
						"standard=%v, alt1(compact)=%v, alt2(mixed)=%v. "+
						"Input: [x.C1(%d), x.C0(%d), y.C1(%d), y.C0(%d)] = %d bytes. "+
						"Standard compressed: %x (first 16 bytes), "+
						"Alt1 compressed: %x (first 16 bytes), "+
						"Alt2 compressed: %x (first 16 bytes)",
						err, errAlt, errAlt2, len(xC1Bytes), len(xC0Bytes), len(yC1Bytes), len(yC0Bytes), 256,
						compressed[:16], compressedAlt[:16], compressedAlt2[:16])
				}
				bytesReadAlt = bytesReadAlt2
				errAlt = nil
				fmt.Fprintf(os.Stderr, "    Format 2 succeeded\n")
			} else {
				fmt.Fprintf(os.Stderr, "    Format 1 (compact) succeeded\n")
			}
			if bytesReadAlt != 96 {
				return bls.G2Affine{}, fmt.Errorf("SetBytes(alternative) read %d bytes, expected 96", bytesReadAlt)
			}
			fmt.Fprintf(os.Stderr, "  Successfully parsed using alternative location\n")
		} else {
			return bls.G2Affine{}, fmt.Errorf("failed to parse G2 point from compressed format: %v. "+
				"Input: [x.C1(%d), x.C0(%d), y.C1(%d), y.C0(%d)] = %d bytes. "+
				"Compressed format: %x (first 16 bytes)",
				err, len(xC1Bytes), len(xC0Bytes), len(yC1Bytes), len(yC0Bytes), 256, compressed[:16])
		}
	}
	if bytesRead != 96 {
		return bls.G2Affine{}, fmt.Errorf("SetBytes read %d bytes, expected 96", bytesRead)
	}

	// Verify the point is on the curve
	if !g2Point.IsOnCurve() {
		return bls.G2Affine{}, fmt.Errorf("point is not on the curve")
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

	// Check if first argument is "manual", "random", "ethereum", "g1add", "g2add", "g1mul", "g2mul", "pairing", "pairing-random", or "g2add-random"
	mode := os.Args[1]
	if mode == "g2add-random" {
		// G2 addition random mode
		runG2AddRandomMode()
	} else if mode == "pairing-random" {
		// Pairing random mode (generates test scenarios including bilinearity test)
		runPairingRandomMode()
	} else if mode == "pairing" {
		// Pairing operation mode
		pairingFlags := flag.NewFlagSet("pairing", flag.ExitOnError)
		inputHex := pairingFlags.String("input", "", "Ethereum format input hex string (G1+G2 pairs, each pair is 384 bytes)")

		if err := pairingFlags.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
			printUsage()
			os.Exit(1)
		}

		if *inputHex == "" {
			fmt.Fprintf(os.Stderr, "Error: --input is required\n")
			printUsage()
			os.Exit(1)
		}

		result, err := computePairing(*inputHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Operation: pairing\n")
		fmt.Printf("Input length: %d hex chars\n", len(*inputHex))
		fmt.Printf("Result (32 bytes, 64 hex chars): %s\n", result)
		fmt.Println("This result can be compared with Neo invokescript output")
	} else if mode == "g1add" || mode == "g2add" || mode == "g1mul" || mode == "g2mul" {
		// Add/Mul operations mode
		addMulFlags := flag.NewFlagSet(mode, flag.ExitOnError)
		inputHex := addMulFlags.String("input", "", "Ethereum format input hex string")

		if err := addMulFlags.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
			printUsage()
			os.Exit(1)
		}

		if *inputHex == "" {
			fmt.Fprintf(os.Stderr, "Error: --input is required\n")
			printUsage()
			os.Exit(1)
		}

		var result string
		var err error

		switch mode {
		case "g1add":
			result, err = computeG1Add(*inputHex)
		case "g2add":
			result, err = computeG2Add(*inputHex)
		case "g1mul":
			result, err = computeG1Mul(*inputHex)
		case "g2mul":
			result, err = computeG2Mul(*inputHex)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Operation: %s\n", mode)
		fmt.Printf("Input length: %d hex chars\n", len(*inputHex))
		fmt.Printf("Result (Ethereum format, %d hex chars): %s\n", len(result), result)
		fmt.Println("This result can be compared with Neo invokescript output")
	} else if mode == "ethereum" {
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
