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

using Neo.Cryptography.BLS12_381;
using Neo.Extensions;
using Neo.SmartContract;
using Neo.SmartContract.Native;
using Neo.VM;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.InteropServices;

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
        "ab22c09dcc1bd0fe96227e42a31a61ea3250827a36cb16ae2fecbcc246b26adcd26ab339f6e65fb8b649b58ad084086517fe0917791401e52703d1317dfe5db1b8b9c7a189f4501969d303bd0f359e13ade27fb3bc1143214311f8581bcebabc",
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
    private static readonly string G2_HEX = "ab22c09dcc1bd0fe96227e42a31a61ea3250827a36cb16ae2fecbcc246b26adcd26ab339f6e65fb8b649b58ad084086517fe0917791401e52703d1317dfe5db1b8b9c7a189f4501969d303bd0f359e13ade27fb3bc1143214311f8581bcebabc";

    // ============================================
    // Configuration: Operation Type
    // ============================================
    // Operation types: "multiexp", "g1add", "g2add", "g1mul", "g2mul"
    private static readonly string OPERATION_TYPE = "g2add";
    
    // For Add operations: second point (compressed format)
    // For Mul operations: scalar value
    private static readonly string G1_SECOND_POINT_HEX = "a195fab58325ffd54c08d3b180d2275ca2b45ab91623a5d6b330d88d25f0754b7259e710636296e583c8be33e968860d"; // Same as G1_HEX for testing
    private static readonly string G2_SECOND_POINT_HEX = "95d7dc07e5eaf185910d9fad2dd69fabb971b3113540a4a411b1d568f5bb6b1fa1bac6bb97a638b204fe5bbac6be140a10bacf59b3e520f1d9ab073377b8c2718ed556852004eb6cec6e153cbbae4e1891a05f5dbae38cead62004d3b37e5f36"; // Same as G2_HEX for testing
    private static readonly BigInteger MUL_SCALAR = 2; // Scalar for Mul operations

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
        // Determine if we should use G2 based on OPERATION_TYPE or USE_G2
        bool useG2;
        if (!string.IsNullOrEmpty(OPERATION_TYPE))
        {
            string opType = OPERATION_TYPE.ToLower();
            useG2 = opType == "g2add" || opType == "g2mul";
        }
        else
        {
            useG2 = USE_G2;
        }
        
        string[] points = useG2 ? G2_POINTS : G1_POINTS;
        string fallbackHex = useG2 ? G2_HEX : G1_HEX;
        
        // If points array is empty, use fallback (backward compatibility)
        if (points.Length == 0)
        {
            return fallbackHex;
        }
        
        // Use point at index, wrapping around if index exceeds array length
        return points[index % points.Length];
    }

    /// <summary>
    /// Encode G1 point to Ethereum format (128 bytes)
    /// </summary>
    private static byte[] EncodeEthereumG1Point(G1Affine point)
    {
        const int Bls12FieldElementLength = 64;
        const int Bls12G1EncodedLength = 128;
        const int FpSize = 48;
        
        if (point.IsIdentity)
            return new byte[Bls12G1EncodedLength];
        
        byte[] output = new byte[Bls12G1EncodedLength];
        // Clear the output array to ensure padding bytes are zero (matching Neo's WriteEthereumFp implementation)
        Array.Clear(output);
        
        // Write X coordinate (64 bytes: first 16 bytes are 0, last 48 bytes are the value)
        Span<byte> xBuffer = stackalloc byte[FpSize];
        point.X.TryWrite(xBuffer);
        xBuffer.CopyTo(output.AsSpan(Bls12FieldElementLength - FpSize, FpSize));
        
        // Write Y coordinate (64 bytes: first 16 bytes are 0, last 48 bytes are the value)
        Span<byte> yBuffer = stackalloc byte[FpSize];
        point.Y.TryWrite(yBuffer);
        yBuffer.CopyTo(output.AsSpan(Bls12FieldElementLength * 2 - FpSize, FpSize));
        
        return output;
    }

    /// <summary>
    /// Encode G2 point to Ethereum format (256 bytes)
    /// </summary>
    private static byte[] EncodeEthereumG2Point(G2Affine point)
    {
        const int Bls12FieldElementLength = 64;
        const int Bls12G2EncodedLength = 256;
        const int FpSize = 48;
        
        if (point.IsIdentity)
            return new byte[Bls12G2EncodedLength];
        
        byte[] output = new byte[Bls12G2EncodedLength];
        // Clear the output array to ensure padding bytes are zero (matching Neo's WriteEthereumFp implementation)
        Array.Clear(output);
        
        // Ethereum format: [x.C0 (64 bytes), x.C1 (64 bytes), y.C0 (64 bytes), y.C1 (64 bytes)]
        // Each 64-byte field: first 16 bytes are 0, last 48 bytes are the value
        // This matches Neo's EncodeEthereumG2 implementation
        
        // x.C0: output[0..64], write to output[16..64]
        // Match Neo's WriteEthereumFp implementation: Clear the span, then copy to the last 48 bytes
        Span<byte> xC0Span = output.AsSpan(0, Bls12FieldElementLength);
        xC0Span.Clear(); // Ensure padding bytes (0-15) are zero
        Span<byte> buffer = stackalloc byte[FpSize];
        if (!point.X.C0.TryWrite(buffer))
        {
            throw new InvalidOperationException("Failed to write X.C0 to buffer");
        }
        // Copy to last 48 bytes of the 64-byte field (bytes 16-64)
        // xC0Span[(Bls12FieldElementLength - FpSize)..] = xC0Span[16..64] = output[16..64]
        Span<byte> targetSpan = xC0Span[(Bls12FieldElementLength - FpSize)..];
        buffer.CopyTo(targetSpan);
        
        // Verify: Check that padding bytes (0-15) are still zero after copy
        for (int i = 0; i < 16; i++)
        {
            if (xC0Span[i] != 0)
            {
                throw new InvalidOperationException($"x.C0 padding byte[{i}] is non-zero (0x{xC0Span[i]:X2}) after copy. This indicates a bug in EncodeEthereumG2Point.");
            }
        }
        
        // x.C1: output[64..128], write to output[80..128]
        Span<byte> xC1Span = output.AsSpan(Bls12FieldElementLength, Bls12FieldElementLength);
        xC1Span.Clear();
        buffer.Clear(); // Clear buffer before reuse
        point.X.C1.TryWrite(buffer);
        buffer.CopyTo(xC1Span[(Bls12FieldElementLength - FpSize)..]);
        
        // y.C0: output[128..192], write to output[144..192]
        Span<byte> yC0Span = output.AsSpan(Bls12FieldElementLength * 2, Bls12FieldElementLength);
        yC0Span.Clear();
        buffer.Clear(); // Clear buffer before reuse
        point.Y.C0.TryWrite(buffer);
        buffer.CopyTo(yC0Span[(Bls12FieldElementLength - FpSize)..]);
        
        // y.C1: output[192..256], write to output[208..256]
        Span<byte> yC1Span = output.AsSpan(Bls12FieldElementLength * 3, Bls12FieldElementLength);
        yC1Span.Clear();
        buffer.Clear(); // Clear buffer before reuse
        point.Y.C1.TryWrite(buffer);
        buffer.CopyTo(yC1Span[(Bls12FieldElementLength - FpSize)..]);
        
        return output;
    }

    /// <summary>
    /// Create script to call bls12_g1add (Ethereum format)
    /// Input: two G1 points in Ethereum format (128 bytes each = 256 bytes total)
    /// </summary>
    public static byte[] CreateG1AddScript()
    {
        using ScriptBuilder script = new();
        var cryptoLibHash = NativeContract.CryptoLib.Hash;
        
        // Get first point (compressed format) and convert to Ethereum format
        string point1Hex = GetPointHex(0);
        byte[] point1Compressed = Convert.FromHexString(point1Hex);
        G1Affine point1 = G1Affine.FromCompressed(point1Compressed);
        byte[] point1Ethereum = EncodeEthereumG1Point(point1);
        
        // Get second point (compressed format) and convert to Ethereum format
        string point2Hex = G1_SECOND_POINT_HEX;
        byte[] point2Compressed = Convert.FromHexString(point2Hex);
        G1Affine point2 = G1Affine.FromCompressed(point2Compressed);
        byte[] point2Ethereum = EncodeEthereumG1Point(point2);
        
        // Concatenate: point1 (128 bytes) + point2 (128 bytes) = 256 bytes
        byte[] inputBytes = new byte[256];
        point1Ethereum.CopyTo(inputBytes, 0);
        point2Ethereum.CopyTo(inputBytes, 128);
        
        script.EmitPush(inputBytes);
        script.EmitPush(1);
        script.Emit(OpCode.PACK);
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12_g1add");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        
        return script.ToArray();
    }

    /// <summary>
    /// Create script to call bls12_g2add (Ethereum format)
    /// Input: two G2 points in Ethereum format (256 bytes each = 512 bytes total)
    /// </summary>
    public static byte[] CreateG2AddScript()
    {
        using ScriptBuilder script = new();
        var cryptoLibHash = NativeContract.CryptoLib.Hash;
        
        // Get first point (compressed format) and convert to Ethereum format
        string point1Hex = GetPointHex(0);
        if (point1Hex.Length != 192)
        {
            throw new InvalidOperationException($"First G2 point must be 192 hex characters (96 bytes), got {point1Hex.Length}. Point hex: {point1Hex.Substring(0, Math.Min(64, point1Hex.Length))}...");
        }
        byte[] point1Compressed = Convert.FromHexString(point1Hex);
        G2Affine point1;
        try
        {
            point1 = G2Affine.FromCompressed(point1Compressed);
        }
        catch (FormatException ex)
        {
            // Provide more detailed error information
            string firstByteHex = point1Hex.Substring(0, 2);
            byte firstByte = point1Compressed[0];
            bool compressionFlag = (firstByte & 0x80) != 0;
            bool infinityFlag = (firstByte & 0x40) != 0;
            bool sortFlag = (firstByte & 0x20) != 0;
            throw new InvalidOperationException(
                $"Failed to parse first G2 point from compressed format: {ex.Message}. " +
                $"Point hex (first 64 chars): {point1Hex.Substring(0, Math.Min(64, point1Hex.Length))}... " +
                $"First byte: 0x{firstByteHex}, flags: compression={compressionFlag}, infinity={infinityFlag}, sort={sortFlag}, " +
                $"data bits: 0x{firstByte & 0x1F:X2}", ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse first G2 point from compressed format: {ex.Message}. Point hex: {point1Hex.Substring(0, Math.Min(64, point1Hex.Length))}...", ex);
        }
        byte[] point1Ethereum = EncodeEthereumG2Point(point1);
        
        // Get second point (compressed format) and convert to Ethereum format
        string point2Hex = G2_SECOND_POINT_HEX;
        if (point2Hex.Length != 192)
        {
            throw new InvalidOperationException($"Second G2 point must be 192 hex characters (96 bytes), got {point2Hex.Length}. Point hex: {point2Hex.Substring(0, Math.Min(64, point2Hex.Length))}...");
        }
        byte[] point2Compressed = Convert.FromHexString(point2Hex);
        G2Affine point2;
        try
        {
            point2 = G2Affine.FromCompressed(point2Compressed);
        }
        catch (FormatException ex)
        {
            // Provide more detailed error information
            string firstByteHex = point2Hex.Substring(0, 2);
            byte firstByte = point2Compressed[0];
            bool compressionFlag = (firstByte & 0x80) != 0;
            bool infinityFlag = (firstByte & 0x40) != 0;
            bool sortFlag = (firstByte & 0x20) != 0;
            throw new InvalidOperationException(
                $"Failed to parse second G2 point from compressed format: {ex.Message}. " +
                $"Point hex (first 64 chars): {point2Hex.Substring(0, Math.Min(64, point2Hex.Length))}... " +
                $"First byte: 0x{firstByteHex}, flags: compression={compressionFlag}, infinity={infinityFlag}, sort={sortFlag}, " +
                $"data bits: 0x{firstByte & 0x1F:X2}", ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse second G2 point from compressed format: {ex.Message}. Point hex: {point2Hex.Substring(0, Math.Min(64, point2Hex.Length))}...", ex);
        }
        byte[] point2Ethereum = EncodeEthereumG2Point(point2);
        
        // Debug: Verify padding bytes are zero for point2 (this should never happen if EncodeEthereumG2Point is correct)
        bool hasNonZeroPadding = false;
        List<string> paddingErrors = new List<string>();
        for (int i = 0; i < 16; i++)
        {
            if (point2Ethereum[i] != 0)
            {
                hasNonZeroPadding = true;
                paddingErrors.Add($"x.C0[{i}]=0x{point2Ethereum[i]:X2}");
            }
            if (point2Ethereum[64 + i] != 0)
            {
                hasNonZeroPadding = true;
                paddingErrors.Add($"x.C1[{i}]=0x{point2Ethereum[64 + i]:X2}");
            }
            if (point2Ethereum[128 + i] != 0)
            {
                hasNonZeroPadding = true;
                paddingErrors.Add($"y.C0[{i}]=0x{point2Ethereum[128 + i]:X2}");
            }
            if (point2Ethereum[192 + i] != 0)
            {
                hasNonZeroPadding = true;
                paddingErrors.Add($"y.C1[{i}]=0x{point2Ethereum[192 + i]:X2}");
            }
        }
        if (hasNonZeroPadding)
        {
            // This should never happen if EncodeEthereumG2Point is correct
            // Throw an exception to catch the bug
            throw new InvalidOperationException(
                $"point2Ethereum has non-zero padding bytes: [{string.Join(" ", paddingErrors)}]. " +
                $"This indicates a bug in EncodeEthereumG2Point. " +
                $"x.C0 data (bytes 16-64): {Convert.ToHexString(point2Ethereum[16..64])}, " +
                $"x.C0 padding (bytes 0-16): {Convert.ToHexString(point2Ethereum[0..16])}");
        }
        
        // Concatenate: point1 (256 bytes) + point2 (256 bytes) = 512 bytes
        byte[] inputBytes = new byte[512];
        point1Ethereum.CopyTo(inputBytes, 0);
        point2Ethereum.CopyTo(inputBytes, 256);
        
        script.EmitPush(inputBytes);
        script.EmitPush(1);
        script.Emit(OpCode.PACK);
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12_g2add");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        
        return script.ToArray();
    }

    /// <summary>
    /// Create script to call bls12_g1mul (Ethereum format)
    /// Input: G1 point (128 bytes) + scalar (32 bytes) = 160 bytes total
    /// </summary>
    public static byte[] CreateG1MulScript()
    {
        using ScriptBuilder script = new();
        var cryptoLibHash = NativeContract.CryptoLib.Hash;
        
        // Get point (compressed format) and convert to Ethereum format
        string pointHex = GetPointHex(0);
        byte[] pointCompressed = Convert.FromHexString(pointHex);
        G1Affine point = G1Affine.FromCompressed(pointCompressed);
        byte[] pointEthereum = EncodeEthereumG1Point(point);
        
        // Get scalar (big-endian, 32 bytes)
        byte[] scalarBytes = CreateScalarBytes(MUL_SCALAR);
        
        // Concatenate: point (128 bytes) + scalar (32 bytes) = 160 bytes
        byte[] inputBytes = new byte[160];
        pointEthereum.CopyTo(inputBytes, 0);
        scalarBytes.CopyTo(inputBytes, 128);
        
        script.EmitPush(inputBytes);
        script.EmitPush(1);
        script.Emit(OpCode.PACK);
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12_g1mul");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        
        return script.ToArray();
    }

    /// <summary>
    /// Create script to call bls12_g2mul (Ethereum format)
    /// Input: G2 point (256 bytes) + scalar (32 bytes) = 288 bytes total
    /// </summary>
    public static byte[] CreateG2MulScript()
    {
        using ScriptBuilder script = new();
        var cryptoLibHash = NativeContract.CryptoLib.Hash;
        
        // Get point (compressed format) and convert to Ethereum format
        string pointHex = GetPointHex(0);
        byte[] pointCompressed = Convert.FromHexString(pointHex);
        G2Affine point;
        try
        {
            point = G2Affine.FromCompressed(pointCompressed);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse G2 point from compressed format: {ex.Message}. Point hex: {pointHex.Substring(0, Math.Min(64, pointHex.Length))}...", ex);
        }
        byte[] pointEthereum = EncodeEthereumG2Point(point);
        
        // Get scalar (big-endian, 32 bytes)
        byte[] scalarBytes = CreateScalarBytes(MUL_SCALAR);
        
        // Concatenate: point (256 bytes) + scalar (32 bytes) = 288 bytes
        byte[] inputBytes = new byte[288];
        pointEthereum.CopyTo(inputBytes, 0);
        scalarBytes.CopyTo(inputBytes, 256);
        
        script.EmitPush(inputBytes);
        script.EmitPush(1);
        script.Emit(OpCode.PACK);
        script.EmitPush(CallFlags.All);
        script.EmitPush("bls12_g2mul");
        script.EmitPush(cryptoLibHash);
        script.EmitSysCall(ApplicationEngine.System_Contract_Call);
        
        return script.ToArray();
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
            byte[] script;
            string operationName;
            
            // Generate script based on operation type
            switch (OPERATION_TYPE.ToLower())
            {
                case "g1add":
                    script = CreateG1AddScript();
                    operationName = "bls12_g1add";
                    break;
                case "g2add":
                    script = CreateG2AddScript();
                    operationName = "bls12_g2add";
                    break;
                case "g1mul":
                    script = CreateG1MulScript();
                    operationName = "bls12_g1mul";
                    break;
                case "g2mul":
                    script = CreateG2MulScript();
                    operationName = "bls12_g2mul";
                    break;
                case "multiexp":
                default:
                    // Validate configuration for MultiExp
                    if (SCALARS.Length == 0)
                    {
                        Console.WriteLine("Error: Please provide at least one scalar value!");
                        return;
                    }
                    script = CreateMultiExpScript();
                    operationName = "bls12381MultiExp";
                    break;
            }

            // Validate points configuration (only for MultiExp operations)
            if (OPERATION_TYPE.ToLower() == "multiexp")
            {
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
            }

            // Output results
            Console.WriteLine($"=== {operationName} Call Script Generated ===");
            Console.WriteLine();
            
            // For Add/Mul operations, show operation info
            if (OPERATION_TYPE.ToLower() != "multiexp")
            {
                Console.WriteLine($"Operation: {operationName}");
                if (OPERATION_TYPE.ToLower().Contains("add"))
                {
                    Console.WriteLine($"  Adding two {(USE_G2 ? "G2" : "G1")} points");
                }
                else if (OPERATION_TYPE.ToLower().Contains("mul"))
                {
                    Console.WriteLine($"  Multiplying {(USE_G2 ? "G2" : "G1")} point by scalar");
                }
            }
            else
            {
                // MultiExp specific output
                string[] points = USE_G2 ? G2_POINTS : G1_POINTS;
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
            }
            
            Console.WriteLine();
            Console.WriteLine("Base64 encoding (for Neo CLI):");
            Console.WriteLine(Convert.ToBase64String(script));
            Console.WriteLine();
            Console.WriteLine("Hexadecimal encoding:");
            Console.WriteLine(Convert.ToHexString(script));
            
            // Output Ethereum format input for pairing_gen.go verification (for Add/Mul operations)
            if (OPERATION_TYPE.ToLower() != "multiexp")
            {
                string inputHex = "";
                if (OPERATION_TYPE.ToLower() == "g1add")
                {
                    string point1Hex = GetPointHex(0);
                    string point2Hex = G1_SECOND_POINT_HEX;
                    byte[] point1Compressed = Convert.FromHexString(point1Hex);
                    byte[] point2Compressed = Convert.FromHexString(point2Hex);
                    G1Affine point1 = G1Affine.FromCompressed(point1Compressed);
                    G1Affine point2 = G1Affine.FromCompressed(point2Compressed);
                    byte[] point1Ethereum = EncodeEthereumG1Point(point1);
                    byte[] point2Ethereum = EncodeEthereumG1Point(point2);
                    byte[] inputBytes = new byte[256];
                    point1Ethereum.CopyTo(inputBytes, 0);
                    point2Ethereum.CopyTo(inputBytes, 128);
                    inputHex = Convert.ToHexString(inputBytes);
                }
                else if (OPERATION_TYPE.ToLower() == "g2add")
                {
                    string point1Hex = GetPointHex(0);
                    string point2Hex = G2_SECOND_POINT_HEX;
                    byte[] point1Compressed = Convert.FromHexString(point1Hex);
                    byte[] point2Compressed = Convert.FromHexString(point2Hex);
                    G2Affine point1 = G2Affine.FromCompressed(point1Compressed);
                    G2Affine point2 = G2Affine.FromCompressed(point2Compressed);
                    byte[] point1Ethereum = EncodeEthereumG2Point(point1);
                    byte[] point2Ethereum = EncodeEthereumG2Point(point2);
                    byte[] inputBytes = new byte[512];
                    point1Ethereum.CopyTo(inputBytes, 0);
                    point2Ethereum.CopyTo(inputBytes, 256);
                    inputHex = Convert.ToHexString(inputBytes);
                }
                else if (OPERATION_TYPE.ToLower() == "g1mul")
                {
                    string pointHex = GetPointHex(0);
                    byte[] pointCompressed = Convert.FromHexString(pointHex);
                    G1Affine point = G1Affine.FromCompressed(pointCompressed);
                    byte[] pointEthereum = EncodeEthereumG1Point(point);
                    byte[] scalarBytes = CreateScalarBytes(MUL_SCALAR);
                    byte[] inputBytes = new byte[160];
                    pointEthereum.CopyTo(inputBytes, 0);
                    scalarBytes.CopyTo(inputBytes, 128);
                    inputHex = Convert.ToHexString(inputBytes);
                }
                else if (OPERATION_TYPE.ToLower() == "g2mul")
                {
                    string pointHex = GetPointHex(0);
                    byte[] pointCompressed = Convert.FromHexString(pointHex);
                    G2Affine point = G2Affine.FromCompressed(pointCompressed);
                    byte[] pointEthereum = EncodeEthereumG2Point(point);
                    byte[] scalarBytes = CreateScalarBytes(MUL_SCALAR);
                    byte[] inputBytes = new byte[288];
                    pointEthereum.CopyTo(inputBytes, 0);
                    scalarBytes.CopyTo(inputBytes, 256);
                    inputHex = Convert.ToHexString(inputBytes);
                }
                
                if (!string.IsNullOrEmpty(inputHex))
                {
                    Console.WriteLine();
                    Console.WriteLine($"Ethereum format input (for pairing_gen.go {OPERATION_TYPE}):");
                    Console.WriteLine(inputHex);
                }
            }
            
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

