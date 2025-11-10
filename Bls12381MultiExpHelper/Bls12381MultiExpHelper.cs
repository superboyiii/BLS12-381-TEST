// Copyright (C) 2015-2025 The Neo Project.
//
// Bls12381MultiExpHelper.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Neo.Extensions;
using Neo.SmartContract;
using Neo.SmartContract.Native;
using Neo.VM;
using System;
using System.Numerics;

public class Bls12381MultiExpHelper
{
    // ============================================
    // Configuration Area: Modify these values with your actual data
    // ============================================

    // ============================================
    // Configuration: Points and Scalars
    // ============================================
    
    // G1 points array (each point is 48 bytes, 96 hex characters)
    // If you have multiple different points, add them here
    // If you only have one point, it will be repeated for all pairs
    // Example: Use different points for comprehensive testing
    private static readonly string[] G1_POINTS = new string[]
    {
        "a195fab58325ffd54c08d3b180d2275ca2b45ab91623a5d6b330d88d25f0754b7259e710636296e583c8be33e968860d",
        // Add more G1 points here if needed for testing different points
    };

    // G2 points array (each point is 96 bytes, 192 hex characters)
    // If you have multiple different points, add them here
    // If you only have one point, it will be repeated for all pairs
    private static readonly string[] G2_POINTS = new string[]
    {
        "a4eaf10f48781d663bf03d046d50c902088b97cd35ccbdd3fffbc2ee5cd95dc00c8894dbc84a3390cd95dcbf50ef9ece176b5efc0cba714ae43df47dd9d408daa5852cd6b47ccc2e504c7ad3e0829196d1e5a4d381edf08f8067a88c25dda003",
        // Add more G2 points here if needed for testing different points
    };

    // Scalar values array (each value corresponds to a point)
    // 
    // MultiExp calculation: point₁ × scalar₁ + point₂ × scalar₂ + point₃ × scalar₃ + ...
    //
    // Scalar value selection suggestions:
    // 1. Testing/Demo: Use simple values [1, 2, 3] or [1, 1, 1] (recommended for initial testing)
    // 2. Equal weights: All scalar values are the same, e.g., [1, 1, 1] or [10, 10, 10]
    // 3. Different weights: Weighted distribution, e.g., [10, 5, 1] (for weighted voting, etc.)
    // 4. BLS signature aggregation: Use hash values to generate scalars (for signature aggregation)
    // 5. Security applications: Use random numbers to generate scalars (for cryptographic security scenarios)
    //
    // For more details, see: neo/scripts/SCALAR_SELECTION_GUIDE.md
    //
    private static readonly BigInteger[] SCALARS = new BigInteger[] { 1583818600, 259712423, 351930380, 672431045, 1472502201, 1412881703, 1986147645, 40099964, 142141369, 732322170, 933771271, 65086840, 1184612915, 1680742504, 1158217810, 2039254395, 1416164542, 2001641051, 2130393976, 638429679, 1599045576, 714952986, 640858308, 1656854782, 1266185637, 1068163509, 1092415352, 639808918, 1902890949, 416042511, 616982101, 1316086158, 1632105853, 2120684624, 729259342, 1053306010, 656282246, 47399725, 842859189, 1455693148, 79808309, 1612795530, 1956796088, 2044798900, 352651851, 218623658, 731756968, 1792731369, 718146579, 432156565, 1303415108, 761784416, 1121530192, 974705024, 592267398, 2014094771, 1503133634, 993560109, 1065210562, 207569219, 1161251998, 974218387, 1289815564, 1544407688, 1379403943, 2059038431, 1615325352, 1638777115, 1365858113, 2128484506, 1908622647, 530845493, 486591571, 1380970200, 403596093, 1115521402, 45588979 };
    
    // Whether to use G2 point (true = G2, false = G1)
    private static readonly bool USE_G2 = false;
    
    // Backward compatibility: Legacy single point support
    // If G1_POINTS or G2_POINTS is empty, these will be used
    private static readonly string G1_HEX = "a195fab58325ffd54c08d3b180d2275ca2b45ab91623a5d6b330d88d25f0754b7259e710636296e583c8be33e968860d";
    private static readonly string G2_HEX = "a4eaf10f48781d663bf03d046d50c902088b97cd35ccbdd3fffbc2ee5cd95dc00c8894dbc84a3390cd95dcbf50ef9ece176b5efc0cba714ae43df47dd9d408daa5852cd6b47ccc2e504c7ad3e0829196d1e5a4d381edf08f8067a88c25dda003";

    // ============================================

    /// <summary>
    /// Convert BigInteger to 32-byte scalar (big-endian)
    /// Note: Bls12381MultiExp.ParseScalar expects big-endian input and converts it to little-endian internally
    /// This implementation matches the test code in UT_CryptoLib.cs
    /// </summary>
    private static byte[] CreateScalarBytes(BigInteger value)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(nameof(value));

        var bytes = new byte[32]; // Scalar.Size = 32
        var mask = (BigInteger.One << 256) - BigInteger.One;
        var truncated = value & mask;

        // Use ToByteArray to ensure proper big-endian encoding with right-alignment
        var encoded = truncated.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (encoded.Length > 32)
            throw new InvalidOperationException("Unable to encode scalar value.");

        // Right-align: copy to the end of the array (big-endian format)
        // If encoded.Length < 32, zeros will be at the beginning
        encoded.CopyTo(bytes, 32 - encoded.Length);

        return bytes;
    }

    /// <summary>
    /// Get point hex string for a given index
    /// Supports multiple different points or falls back to single point
    /// </summary>
    private static string GetPointHex(int index)
    {
        string[] points = USE_G2 ? G2_POINTS : G1_POINTS;
        string fallbackHex = USE_G2 ? G2_HEX : G1_HEX;
        
        // If points array is empty, use fallback (backward compatibility)
        if (points.Length == 0)
        {
            return fallbackHex;
        }
        
        // Use point at index, wrapping around if index exceeds array length
        return points[index % points.Length];
    }

    /// <summary>
    /// Create script to call Bls12381MultiExp
    /// Supports multiple different points for comprehensive testing
    /// </summary>
    public static byte[] CreateMultiExpScript()
    {
        using ScriptBuilder script = new();
        var cryptoLibHash = NativeContract.CryptoLib.Hash;

        int pairCount = SCALARS.Length;
        int expectedPointLength = USE_G2 ? 192 : 96; // G2: 96 bytes = 192 chars, G1: 48 bytes = 96 chars

        // Construct [point, scalar] for each pair
        // Note: PACK takes elements from the top of the stack, so to get [point, scalar],
        // we need to push scalar first, then push point, so the stack is [scalar, point] (bottom to top),
        // PACK 2 will take point first, then scalar, creating [point, scalar]
        for (int i = 0; i < pairCount; i++)
        {
            // Get point for this pair (supports multiple different points)
            string pointHex = GetPointHex(i);
            
            // Validate point hex length
            if (pointHex.Length != expectedPointLength)
            {
                throw new InvalidOperationException(
                    $"Point at index {i} has invalid length: {pointHex.Length} characters, expected {expectedPointLength} characters");
            }
            
            byte[] pointBytes = Convert.FromHexString(pointHex);
            
            // Push scalar first (so it will be at the bottom of the stack)
            byte[] scalarBytes = CreateScalarBytes(SCALARS[i]);
            
            // Debug output: verify point-scalar pairs match pairing_gen.go
            // This will help identify if points and scalars are correctly matched
            if (i < 5 || i >= pairCount - 2) // Output first 5 and last 2 pairs for debugging
            {
                Console.Error.WriteLine($"  Pair[{i}]: point = {pointHex.Substring(0, Math.Min(32, pointHex.Length))}..., scalar = {SCALARS[i]}");
            }
            
            script.EmitPush(scalarBytes);
            // Stack now: ByteString (scalar)

            // Then deserialize point (so it will be on top of the stack)
            script.EmitDynamicCall(cryptoLibHash, "bls12381Deserialize", pointBytes);
            // Stack now: InteropInterface (point), ByteString (scalar)

            // Construct pair = [point, scalar]
            // PACK 2 takes from top: first point, then scalar, creating [point, scalar]
            script.EmitPush(2);
            script.Emit(OpCode.PACK);
            // Stack now: Array (pair = [point, scalar])
        }

        // Construct pairs array = [pair1, pair2, ...]
        // Stack now has pairCount pair arrays
        script.EmitPush(pairCount);
        script.Emit(OpCode.PACK);
        // Stack now: Array (pairs = [pair1, pair2, ...])

        // Wrap pairs into args array = [pairs]
        // System.Contract.Call requires a parameter array, even if there's only one parameter
        script.EmitPush(1);  // args array has only one element
        script.Emit(OpCode.PACK);
        // Stack now: Array (args = [pairs])

        // Call bls12381MultiExp
        // System.Contract.Call stack order (bottom to top): args, CallFlags, method, contractHash
        // But OnSysCall pops from the top, so the order should be: contractHash, method, CallFlags, args
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12381MultiExp");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        // Stack now: InteropInterface (result from bls12381MultiExp)

        // Serialize return value to view specific content
        // Call bls12381Serialize to convert InteropInterface to byte array
        // bls12381Serialize requires one parameter: InteropInterface (already on stack)
        // Need to wrap InteropInterface into parameter array
        script.EmitPush(1);  // args array has only one element (InteropInterface)
        script.Emit(OpCode.PACK);
        // Stack now: Array (args = [InteropInterface])
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12381Serialize");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        // Stack now: Byte[] (serialized point)

        return script.ToArray();
    }

    /// <summary>
    /// Main function: Generate and print script
    /// </summary>
    public static void Main(string[] args)
    {
        try
        {
            // Validate configuration
            if (SCALARS.Length == 0)
            {
                Console.WriteLine("Error: Please provide at least one scalar value!");
                return;
            }

            // Validate points configuration
            string[] points = USE_G2 ? G2_POINTS : G1_POINTS;
            string fallbackHex = USE_G2 ? G2_HEX : G1_HEX;
            int expectedLength = USE_G2 ? 192 : 96; // G2: 96 bytes = 192 chars, G1: 48 bytes = 96 chars

            if (points.Length == 0 && (fallbackHex == "YOUR_G1_HEX_HERE" || fallbackHex == "YOUR_G2_HEX_HERE"))
            {
                Console.WriteLine($"Error: Please provide at least one {(USE_G2 ? "G2" : "G1")} point!");
                Console.WriteLine($"Either add points to {(USE_G2 ? "G2" : "G1")}_POINTS array or set {(USE_G2 ? "G2" : "G1")}_HEX");
                Console.WriteLine("These values should be obtained from pairing_gen.go output.");
                return;
            }

            // Validate all points in array
            if (points.Length > 0)
            {
                for (int i = 0; i < points.Length; i++)
                {
                    if (points[i].Length != expectedLength)
                    {
                        Console.WriteLine($"Error: Point at index {i} has invalid length: {points[i].Length} characters, expected {expectedLength} characters");
                        return;
                    }
                }
            }
            else
            {
                // Validate fallback point
                if (fallbackHex.Length != expectedLength)
                {
                    Console.WriteLine($"Error: {fallbackHex.Length} characters, expected {expectedLength} characters");
                    Console.WriteLine($"Please check {(USE_G2 ? "G2" : "G1")}_HEX value");
                    return;
                }
            }

            // Create script
            byte[] script = CreateMultiExpScript();

            // Output results
            Console.WriteLine("=== Bls12381MultiExp Call Script Generated ===");
            Console.WriteLine();
            // Reuse points and fallbackHex variables already defined above
            int uniquePoints = points.Length > 0 ? points.Length : 1;
            bool usingMultiplePoints = points.Length > 0;
            
            Console.WriteLine($"Using {(USE_G2 ? "G2" : "G1")} points, {SCALARS.Length} pairs");
            if (usingMultiplePoints)
            {
                Console.WriteLine($"  Unique points: {uniquePoints} (will cycle through for {SCALARS.Length} pairs)");
            }
            else
            {
                Console.WriteLine($"  Using single point (repeated for all pairs)");
            }
            Console.WriteLine($"Scalar values: [{string.Join(", ", SCALARS)}]");
            Console.WriteLine();
            Console.WriteLine("Base64 encoding (for Neo CLI):");
            Console.WriteLine(Convert.ToBase64String(script));
            Console.WriteLine();
            Console.WriteLine("Hexadecimal encoding:");
            Console.WriteLine(Convert.ToHexString(script));
            Console.WriteLine();
            Console.WriteLine("Usage in Neo CLI:");
            Console.WriteLine($"invoke script {Convert.ToBase64String(script)}");
            Console.WriteLine();
            Console.WriteLine("Or use hexadecimal:");
            Console.WriteLine($"invoke script {Convert.ToHexString(script)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }
}

