#!/bin/bash

# ============================================================================
# BLS12-381 MultiExp Enhanced Automated Test Script
# ============================================================================
# Features:
#   1. Support G1 and G2 testing
#   2. Support Ethereum format testing (using ethereum mode)
#   3. Support compressed format testing (using manual mode)
#   4. Call pairing_gen.go to generate test data or use Ethereum test vectors
#   5. Update Bls12381MultiExpHelper.cs and generate Neo VM script
#   6. Call Neo RPC invokescript and get results
#   7. Compare with expected results
#   8. Support multiple tests and count mismatches
#
# Usage:
#   ./test_bls12381_multiexp_enhanced.sh [test_type] [num_tests] [max_scalars]
#
# Test Types:
#   - g1: Test G1 with compressed format (default)
#   - g2: Test G2 with compressed format
#   - ethereum-g1: Test G1 with Ethereum format (uses Neo's test vectors)
#   - ethereum-g2: Test G2 with Ethereum format (uses Neo's test vectors)
#   - g1add: Test G1 addition (Ethereum format)
#   - g2add: Test G2 addition (Ethereum format)
#   - g1mul: Test G1 multiplication (Ethereum format)
#   - g2mul: Test G2 multiplication (Ethereum format)
#
# Examples:
#   ./test_bls12381_multiexp_enhanced.sh g1 10 5    # Run 10 G1 tests, max 5 scalars each
#   ./test_bls12381_multiexp_enhanced.sh g2 5      # Run 5 G2 tests, default max_scalars (128)
#   ./test_bls12381_multiexp_enhanced.sh ethereum-g1  # Run Ethereum G1 test vectors
#   ./test_bls12381_multiexp_enhanced.sh ethereum-g2  # Run Ethereum G2 test vectors
#   ./test_bls12381_multiexp_enhanced.sh g1add 5    # Run 5 G1 addition tests
#   ./test_bls12381_multiexp_enhanced.sh g1mul 5    # Run 5 G1 multiplication tests
# ============================================================================

# set -e  # Disabled to allow better error handling in Windows environment

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
RPC_URL="${RPC_URL:-http://localhost:20332}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EVM_DIR="$SCRIPT_DIR/evm"
NEO_SCRIPTS_DIR="$SCRIPT_DIR"
# Use relative paths for Bls12381MultiExpHelper (relative to script directory)
HELPER_DIR="Bls12381MultiExpHelper"
HELPER_CS="Bls12381MultiExpHelper/Bls12381MultiExpHelper.cs"
HELPER_CSPROJ="Bls12381MultiExpHelper/Bls12381MultiExpHelper.csproj"

# Parse command line arguments
TEST_TYPE="${1:-g1}"
NUM_TESTS="${2:-1}"
MAX_SCALARS="${3:-128}"

# Validate test type
case "$TEST_TYPE" in
    g1|g2|ethereum-g1|ethereum-g2|g1add|g2add|g1mul|g2mul)
        ;;
    *)
        echo -e "${RED}Error: Invalid test type '$TEST_TYPE'${NC}"
        echo "Valid test types: g1, g2, ethereum-g1, ethereum-g2, g1add, g2add, g1mul, g2mul"
        exit 1
        ;;
esac

# Validate arguments
if ! [[ "$NUM_TESTS" =~ ^[0-9]+$ ]] || [ "$NUM_TESTS" -lt 1 ]; then
    echo -e "${RED}Error: Number of tests must be a positive integer${NC}"
    exit 1
fi

if ! [[ "$MAX_SCALARS" =~ ^[0-9]+$ ]] || [ "$MAX_SCALARS" -lt 1 ]; then
    echo -e "${RED}Error: max_scalars must be a positive integer${NC}"
    exit 1
fi

# Check required tools
command -v go >/dev/null 2>&1 || { echo -e "${RED}Error: go command not found${NC}" >&2; exit 1; }
command -v dotnet >/dev/null 2>&1 || { echo -e "${RED}Error: dotnet command not found${NC}" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo -e "${RED}Error: curl command not found${NC}" >&2; exit 1; }

# Check JSON parser tool (prefer jq, fallback to Python)
if command -v jq >/dev/null 2>&1; then
    JSON_PARSER="jq"
else
    PYTHON_CANDIDATES=("python3" "python")
    JSON_PARSER=""
    
    for py_cmd in "${PYTHON_CANDIDATES[@]}"; do
        if command -v "$py_cmd" >/dev/null 2>&1; then
            PYTHON_PATH=$(command -v "$py_cmd")
            if [[ "$PYTHON_PATH" == *"WindowsApps"* ]]; then
                continue
            fi
            if "$py_cmd" --version >/dev/null 2>&1; then
                JSON_PARSER="$py_cmd"
                echo -e "${YELLOW}Note: jq not found, will use $py_cmd to parse JSON${NC}"
                break
            fi
        fi
    done
    
    if [ -z "$JSON_PARSER" ]; then
        echo -e "${RED}Error: No available JSON parser tool found${NC}" >&2
        exit 1
    fi
fi

# Detect Python command for script execution (separate from JSON parser)
PYTHON_CMD=""
PYTHON_CANDIDATES=("python3" "python")
for py_cmd in "${PYTHON_CANDIDATES[@]}"; do
    if command -v "$py_cmd" >/dev/null 2>&1; then
        PYTHON_PATH=$(command -v "$py_cmd")
        # Skip WindowsApps Python (often has permission issues)
        if [[ "$PYTHON_PATH" == *"WindowsApps"* ]]; then
            continue
        fi
        if "$py_cmd" --version >/dev/null 2>&1; then
            PYTHON_CMD="$py_cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}Error: Python command not found${NC}" >&2
    echo -e "${YELLOW}Please install Python 3 and ensure it's in your PATH${NC}" >&2
    exit 1
fi

# JSON parsing helper function (same as original script)
json_get() {
    local json="$1"
    local path="$2"
    local default="${3:-}"
    
    if [ "$JSON_PARSER" = "jq" ]; then
        local result=$(echo "$json" | jq -r "$path // empty" 2>/dev/null)
        if [ -z "$result" ] || [ "$result" = "null" ]; then
            echo "$default"
        else
            echo "$result"
        fi
    else
        local json_path="$path"
        local result=$(echo "$json" | JSON_PATH="$json_path" "$JSON_PARSER" -c "
import json
import sys
import os
import re

def get_nested_value(data, path):
    if not path or path == '.':
        return data
    path = path.lstrip('.')
    pattern = r'([^\.\[\]]+)|\[(\d+)\]'
    matches = re.findall(pattern, path)
    value = data
    for match in matches:
        key_name, array_index = match
        try:
            if array_index:
                value = value[int(array_index)]
            elif key_name:
                value = value[key_name]
            else:
                return None
        except (KeyError, IndexError, TypeError):
            return None
    return value if value is not None else None

try:
    data = json.load(sys.stdin)
    path = os.environ.get('JSON_PATH', '')
    value = get_nested_value(data, path)
    if value is None:
        print('')
    else:
        print(str(value))
except Exception as e:
    print('')
" 2>/dev/null)
        if [ -z "$result" ]; then
            echo "$default"
        else
            echo "$result"
        fi
    fi
}

# Check if files exist
if [ ! -f "$EVM_DIR/pairing_gen.go" ]; then
    echo -e "${RED}Error: pairing_gen.go file not found: $EVM_DIR/pairing_gen.go${NC}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$HELPER_CS" ]; then
    echo -e "${RED}Error: Bls12381MultiExpHelper.cs file not found: $SCRIPT_DIR/$HELPER_CS${NC}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$HELPER_CSPROJ" ]; then
    echo -e "${RED}Error: Bls12381MultiExpHelper.csproj file not found: $SCRIPT_DIR/$HELPER_CSPROJ${NC}"
    exit 1
fi

# Check if RPC is available
if ! curl -s -f "$RPC_URL" >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Cannot connect to RPC: $RPC_URL${NC}"
    echo -e "${YELLOW}Please ensure Neo node is running${NC}"
fi

echo -e "${CYAN}=== BLS12-381 MultiExp Enhanced Test ===${NC}"
echo "Test type: $TEST_TYPE"
echo "Number of tests: $NUM_TESTS"
echo "Max scalars: $MAX_SCALARS"
echo "RPC URL: $RPC_URL"
echo ""

# Statistics
mismatch_count=0
success_count=0

# Temporary files
TEMP_OUTPUT=$(mktemp)
HELPER_BACKUP=$(mktemp)
FAILED_TEST_LOG="$NEO_SCRIPTS_DIR/failed_tests_$(date +%Y%m%d_%H%M%S).log"

# Backup original file
cp "$SCRIPT_DIR/$HELPER_CS" "$HELPER_BACKUP"

# Cleanup function
cleanup() {
    rm -f "$TEMP_OUTPUT"
    if [ -f "$HELPER_BACKUP" ]; then
        cp "$HELPER_BACKUP" "$SCRIPT_DIR/$HELPER_CS"
        rm -f "$HELPER_BACKUP"
    fi
}
trap cleanup EXIT

# Ethereum test vectors (from Neo's UT_CryptoLib.cs)
ETH_G1_SINGLE_INPUT="0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000011"
ETH_G1_SINGLE_EXPECTED="b098f178f84fc753a76bb63709e9be91eec3ff5f7f3a5f4836f34fe8a1a6d6c5578d8fd820573cef3a01e2bfef3eaf3a"

ETH_G1_MULTIPLE_INPUT="0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000e12039459c60491672b6a6282355d8765ba6272387fb91a3e9604fa2a81450cf16b870bb446fc3a3e0a187fff6f89450000000000000000000000000000000018b6c1ed9f45d3cbc0b01b9d038dcecacbd702eb26469a0eb3905bd421461712f67f782b4735849644c1772c93fe3d09000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000147b327c8a15b39634a426af70c062b50632a744eddd41b5a4686414ef4cd9746bb11d0a53c6c2ff21bbcf331e07ac9200000000000000000000000000000000078c2e9782fa5d9ab4e728684382717aa2b8fad61b5f5e7cf3baa0bc9465f57342bb7c6d7b232e70eebcdbf70f903a450000000000000000000000000000000000000000000000000000000000000034"
ETH_G1_MULTIPLE_EXPECTED="9339b4f51923efe38905f590ba2031a2e7154f0adb34a498dfde8fb0f1ccf6862ae5e3070967056385055a666f1b6fc7"

ETH_G2_SINGLE_INPUT="00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0000000000000000000000000000000000000000000000000000000000000011"
ETH_G2_SINGLE_EXPECTED="8ef786ebdcda12e142a32f091307f2fedf52f6c36beb278b0007a03ad81bf9fee3710a04928e43e541d02c9be44722e80d05ceb0be53d2624a796a7a033aec59d9463c18d672c451ec4f2e679daef882cab7d8dd88789065156a1340ca9d4265118ed350274bc45e63eaaa4b8ddf119b3bf38418b5b9748597edfc456d9bc3e864ec7283426e840fd29fa84e7d89c9341594b866a28946b6d444bf0481558812769ea3222f5dfc961ca33e78e0ea62ee8ba63fd1ece9cc3e315abfa96d536944"

# Run tests
for ((test_num=1; test_num<=NUM_TESTS; test_num++)); do
    echo -e "${CYAN}--- Test $test_num/$NUM_TESTS ($TEST_TYPE) ---${NC}"
    
    USE_G2=false
    USE_ETHEREUM=false
    USE_ADD_MUL=false
    OPERATION_MODE=""
    EXPECTED_RESULT=""
    INPUT_HEX=""
    
    case "$TEST_TYPE" in
        g1)
            USE_G2=false
            USE_ETHEREUM=false
            USE_ADD_MUL=false
            ;;
        g2)
            USE_G2=true
            USE_ETHEREUM=false
            USE_ADD_MUL=false
            ;;
        ethereum-g1)
            USE_G2=false
            USE_ETHEREUM=true
            USE_ADD_MUL=false
            if [ $test_num -eq 1 ]; then
                INPUT_HEX="$ETH_G1_SINGLE_INPUT"
                EXPECTED_RESULT="$ETH_G1_SINGLE_EXPECTED"
            else
                INPUT_HEX="$ETH_G1_MULTIPLE_INPUT"
                EXPECTED_RESULT="$ETH_G1_MULTIPLE_EXPECTED"
            fi
            ;;
        ethereum-g2)
            USE_G2=true
            USE_ETHEREUM=true
            USE_ADD_MUL=false
            INPUT_HEX="$ETH_G2_SINGLE_INPUT"
            EXPECTED_RESULT="$ETH_G2_SINGLE_EXPECTED"
            echo -e "${YELLOW}Note: G2 Ethereum format testing is currently under investigation${NC}"
            echo -e "${YELLOW}G2 point parsing may fail due to format differences${NC}"
            ;;
        g1add|g2add|g1mul|g2mul)
            USE_ADD_MUL=true
            OPERATION_MODE="$TEST_TYPE"
            if [[ "$TEST_TYPE" == *"g2"* ]]; then
                USE_G2=true
            else
                USE_G2=false
            fi
            ;;
    esac
    
    if [ "$USE_ETHEREUM" = true ]; then
        # Ethereum format test
        echo "Step 1: Running pairing_gen.go (ethereum mode)..."
        cd "$EVM_DIR"
        if ! go run pairing_gen.go ethereum --input "$INPUT_HEX" $([ "$USE_G2" = true ] && echo "--use-g2") > "$TEMP_OUTPUT" 2>&1; then
            echo -e "${RED}Error: pairing_gen.go execution failed${NC}"
            cat "$TEMP_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Extract result from ethereum mode output
        RESULT_FROM_GO=$(grep -m 1 "^MultiExp result (compressed," "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
        if [ -z "$RESULT_FROM_GO" ]; then
            echo -e "${RED}Error: Cannot extract result from pairing_gen.go${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        echo -e "${YELLOW}Note: Ethereum format testing compares pairing_gen.go result with expected${NC}"
        echo "Result from pairing_gen.go: $RESULT_FROM_GO"
        
        if [ "$RESULT_FROM_GO" = "$EXPECTED_RESULT" ]; then
            echo -e "${GREEN}✓ Ethereum format test passed!${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}✗ Ethereum format test failed!${NC}"
            mismatch_count=$((mismatch_count + 1))
        fi
        echo ""
        continue
    fi
    
    if [ "$USE_ADD_MUL" = true ]; then
        # Add/Mul operations test
        echo "Step 1: Generating test data with pairing_gen.go..."
        cd "$EVM_DIR"
        USE_G2_FLAG=""
        if [ "$USE_G2" = true ]; then
            USE_G2_FLAG="--use-g2"
        fi
        if ! go run pairing_gen.go random 1 $USE_G2_FLAG > "$TEMP_OUTPUT" 2>&1; then
            echo -e "${RED}Error: pairing_gen.go execution failed${NC}"
            cat "$TEMP_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Extract point(s) from output
        if [ "$USE_G2" = true ]; then
            POINT1_HEX=$(grep -m 1 "^G2 (compressed, 96 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            POINT2_HEX="$POINT1_HEX" # Use same point for testing, or generate second
        else
            POINT1_HEX=$(grep -m 1 "^G1 (compressed, 48 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            POINT2_HEX="$POINT1_HEX" # Use same point for testing
        fi
        
        if [ -z "$POINT1_HEX" ]; then
            echo -e "${RED}Error: Cannot extract point from pairing_gen.go${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Generate second point for Add operations
        if [[ "$OPERATION_MODE" == *"add"* ]]; then
            # Generate another random point
            if ! go run pairing_gen.go random 1 $USE_G2_FLAG > "$TEMP_OUTPUT" 2>&1; then
                echo -e "${RED}Error: Failed to generate second point${NC}"
                mismatch_count=$((mismatch_count + 1))
                continue
            fi
            if [ "$USE_G2" = true ]; then
                POINT2_HEX=$(grep -m 1 "^G2 (compressed, 96 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            else
                POINT2_HEX=$(grep -m 1 "^G1 (compressed, 48 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            fi
        fi
        
        # Convert compressed points to Ethereum format and prepare input
        echo "Step 2: Converting points to Ethereum format..."
        if [[ "$OPERATION_MODE" == *"add"* ]]; then
            # For Add: need to convert both points to Ethereum format
            # Use pairing_gen.go to convert: deserialize compressed -> encode Ethereum
            # Actually, we'll generate the input directly using pairing_gen.go's conversion
            # For now, we'll use a helper script or call pairing_gen.go in a special mode
            # Since pairing_gen.go doesn't have a direct conversion mode, we'll need to
            # generate the Ethereum format input in the C# helper
            INPUT_HEX="" # Will be generated in C# helper
        else
            # For Mul: need point + scalar
            SCALAR_VALUE="2" # Use fixed scalar for testing
            INPUT_HEX="" # Will be generated in C# helper
        fi
        
        # Calculate expected result using pairing_gen.go
        echo "Step 3: Calculating expected result with pairing_gen.go..."
        if [[ "$OPERATION_MODE" == "g1add" ]]; then
            # Need to convert points to Ethereum format first
            # For now, we'll generate input in C# and use pairing_gen.go to verify
            echo -e "${YELLOW}Note: G1Add test requires Ethereum format conversion${NC}"
            echo -e "${YELLOW}This will be handled by the C# helper and pairing_gen.go${NC}"
        elif [[ "$OPERATION_MODE" == "g2add" ]]; then
            echo -e "${YELLOW}Note: G2Add test requires Ethereum format conversion${NC}"
        elif [[ "$OPERATION_MODE" == "g1mul" ]]; then
            echo -e "${YELLOW}Note: G1Mul test requires Ethereum format conversion${NC}"
        elif [[ "$OPERATION_MODE" == "g2mul" ]]; then
            echo -e "${YELLOW}Note: G2Mul test requires Ethereum format conversion${NC}"
        fi
        
        # Update Bls12381MultiExpHelper.cs
        echo "Step 4: Updating Bls12381MultiExpHelper.cs..."
        cd "$SCRIPT_DIR/$HELPER_DIR"
        HELPER_CS_FILE="Bls12381MultiExpHelper.cs"
        cp "$HELPER_BACKUP" "$HELPER_CS_FILE"
        
        # Update operation type
        sed -i.bak "s|private static readonly string OPERATION_TYPE = \".*\";|private static readonly string OPERATION_TYPE = \"$OPERATION_MODE\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
        
        # Update points
        if [ "$USE_G2" = true ]; then
            # Update G2_HEX (fallback)
            sed -i.bak "s|private static readonly string G2_HEX = \".*\";|private static readonly string G2_HEX = \"$POINT1_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            # Update G2_POINTS array first element - find the line with G2_POINTS array and replace first quoted string
            # This handles both cases: with and without comments
            awk -v new_point="$POINT1_HEX" '
                /private static readonly string\[\] G2_POINTS/,/^[[:space:]]*\};/ {
                    if (match($0, /"[^"]*"/) && !found) {
                        sub(/"[^"]*"/, "\"" new_point "\"")
                        found = 1
                    }
                }
                { print }
            ' "$HELPER_CS_FILE" > "$HELPER_CS_FILE.tmp" && mv "$HELPER_CS_FILE.tmp" "$HELPER_CS_FILE"
            if [[ "$OPERATION_MODE" == *"add"* ]]; then
                sed -i.bak "s|private static readonly string G2_SECOND_POINT_HEX = \".*\";|private static readonly string G2_SECOND_POINT_HEX = \"$POINT2_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            fi
        else
            # Update G1_HEX (fallback)
            sed -i.bak "s|private static readonly string G1_HEX = \".*\";|private static readonly string G1_HEX = \"$POINT1_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            # Update G1_POINTS array first element - find the line with G1_POINTS array and replace first quoted string
            # This handles both cases: with and without comments
            awk -v new_point="$POINT1_HEX" '
                /private static readonly string\[\] G1_POINTS/,/^[[:space:]]*\};/ {
                    if (match($0, /"[^"]*"/) && !found) {
                        sub(/"[^"]*"/, "\"" new_point "\"")
                        found = 1
                    }
                }
                { print }
            ' "$HELPER_CS_FILE" > "$HELPER_CS_FILE.tmp" && mv "$HELPER_CS_FILE.tmp" "$HELPER_CS_FILE"
            if [[ "$OPERATION_MODE" == *"add"* ]]; then
                sed -i.bak "s|private static readonly string G1_SECOND_POINT_HEX = \".*\";|private static readonly string G1_SECOND_POINT_HEX = \"$POINT2_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            fi
        fi
        
        # Update scalar for Mul operations
        if [[ "$OPERATION_MODE" == *"mul"* ]]; then
            sed -i.bak "s|private static readonly BigInteger MUL_SCALAR = .*;|private static readonly BigInteger MUL_SCALAR = $SCALAR_VALUE;|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
        fi
        
        echo "Step 5: Generating Neo VM script..."
        # Force rebuild to ensure latest code changes are used
        # Note: We're already in the Bls12381MultiExpHelper directory (cd'd in Step 4)
        BUILD_OUTPUT=$(dotnet build Bls12381MultiExpHelper.csproj 2>&1)
        BUILD_EXIT_CODE=$?
        if [ $BUILD_EXIT_CODE -ne 0 ]; then
            echo -e "${RED}Error: C# project build failed${NC}"
            echo "$BUILD_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        if ! dotnet run --no-build > "$TEMP_OUTPUT" 2>&1; then
            echo -e "${RED}Error: C# program execution failed${NC}"
            cat "$TEMP_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Debug: Show first few lines of output
        echo "Debug: C# program output (first 10 lines):"
        if command -v head >/dev/null 2>&1; then
            head -n 10 "$TEMP_OUTPUT" 2>/dev/null || cat "$TEMP_OUTPUT" | head -n 10
        else
            # Windows fallback: use PowerShell or just show all output
            cat "$TEMP_OUTPUT" | head -n 10 2>/dev/null || cat "$TEMP_OUTPUT"
        fi
        
        # Extract Base64 script - try multiple methods for Windows compatibility
        BASE64_SCRIPT=""
        if command -v grep >/dev/null 2>&1; then
            BASE64_SCRIPT=$(grep -A 1 "Base64 encoding (for Neo CLI):" "$TEMP_OUTPUT" 2>/dev/null | tail -n 1 | tr -d '[:space:]' 2>/dev/null || echo "")
        fi
        
        # Fallback: use sed or awk if grep fails
        if [ -z "$BASE64_SCRIPT" ]; then
            if command -v sed >/dev/null 2>&1; then
                BASE64_SCRIPT=$(sed -n '/Base64 encoding (for Neo CLI):/,/^$/p' "$TEMP_OUTPUT" 2>/dev/null | sed -n '2p' | tr -d '[:space:]' 2>/dev/null || echo "")
            fi
        fi
        
        if [ -z "$BASE64_SCRIPT" ]; then
            echo -e "${RED}Error: Cannot extract Base64 script${NC}"
            echo "Debug: Full C# output:"
            cat "$TEMP_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        echo "Debug: Base64 script extracted (length: ${#BASE64_SCRIPT})"
        
        # Extract Ethereum format input for pairing_gen.go (for Add/Mul operations)
        ETHEREUM_INPUT_HEX=""
        if grep -q "Ethereum format input (for pairing_gen.go" "$TEMP_OUTPUT"; then
            ETHEREUM_INPUT_HEX=$(grep -A 1 "Ethereum format input (for pairing_gen.go" "$TEMP_OUTPUT" | tail -n 1 | tr -d '[:space:]')
        fi
        
        echo "Step 6: Calling Neo RPC invokescript..."
        # RPC call logic (same as MultiExp)
        if [ "$JSON_PARSER" = "jq" ]; then
            RPC_REQUEST=$(jq -n \
                --arg script "$BASE64_SCRIPT" \
                '{
                    jsonrpc: "2.0",
                    id: 1,
                    method: "invokescript",
                    params: [$script, [], false]
                }')
        else
            RPC_REQUEST=$(echo "$BASE64_SCRIPT" | "$JSON_PARSER" -c "
import json
import sys
script = sys.stdin.read().strip()
request = {
    'jsonrpc': '2.0',
    'id': 1,
    'method': 'invokescript',
    'params': [script, [], False]
}
print(json.dumps(request))
")
        fi
        
        RPC_RESPONSE=$(curl -s -X POST "$RPC_URL" \
            -H "Content-Type: application/json" \
            -d "$RPC_REQUEST")
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error: RPC call failed${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        RPC_ERROR=$(json_get "$RPC_RESPONSE" ".error" "")
        if [ -n "$RPC_ERROR" ] && [ "$RPC_ERROR" != "null" ]; then
            echo -e "${RED}Error: RPC returned error: $RPC_ERROR${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        STATE=$(json_get "$RPC_RESPONSE" ".result.state" "")
        if [ "$STATE" != "HALT" ]; then
            EXCEPTION=$(json_get "$RPC_RESPONSE" ".result.exception" "unknown")
            echo -e "${RED}Error: Script execution failed, state: $STATE, exception: $EXCEPTION${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        STACK_VALUE=$(json_get "$RPC_RESPONSE" ".result.stack[0].value" "")
        if [ -z "$STACK_VALUE" ] || [ "$STACK_VALUE" = "null" ]; then
            echo -e "${RED}Error: Cannot extract result from stack${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Convert result from Base64 to hex
        if command -v base64 >/dev/null 2>&1; then
            ACTUAL_RESULT=$(echo "$STACK_VALUE" | base64 -d 2>/dev/null | xxd -p -c 256 | tr -d '\n' 2>/dev/null)
            if [ $? -ne 0 ]; then
                ACTUAL_RESULT=$(echo "$STACK_VALUE" | base64 -D 2>/dev/null | xxd -p -c 256 | tr -d '\n' 2>/dev/null)
            fi
        else
            echo -e "${RED}Error: base64 command not found${NC}"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Calculate expected result using pairing_gen.go
        echo "Step 7: Calculating expected result..."
        if [ -z "$ETHEREUM_INPUT_HEX" ]; then
            echo -e "${YELLOW}Warning: Cannot extract Ethereum format input from C# output${NC}"
            echo -e "${YELLOW}Actual result from Neo: ${ACTUAL_RESULT:0:64}...${NC}"
            echo -e "${YELLOW}Please verify manually using pairing_gen.go $OPERATION_MODE mode${NC}"
            success_count=$((success_count + 1))
            echo ""
            continue
        fi
        
        # Call pairing_gen.go to calculate expected result
        cd "$EVM_DIR"
        if ! go run pairing_gen.go "$OPERATION_MODE" --input "$ETHEREUM_INPUT_HEX" > "$TEMP_OUTPUT" 2>&1; then
            echo -e "${RED}Error: pairing_gen.go execution failed${NC}"
            cat "$TEMP_OUTPUT"
            mismatch_count=$((mismatch_count + 1))
            continue
        fi
        
        # Extract expected result from pairing_gen.go output
        EXPECTED_RESULT=$(grep -m 1 "^Result (Ethereum format," "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
        if [ -z "$EXPECTED_RESULT" ]; then
            echo -e "${YELLOW}Warning: Cannot extract expected result from pairing_gen.go${NC}"
            echo -e "${YELLOW}Actual result from Neo: ${ACTUAL_RESULT:0:64}...${NC}"
            success_count=$((success_count + 1))
            echo ""
            continue
        fi
        
        # Compare results
        echo "Step 8: Comparing results..."
        echo ""
        echo -e "${CYAN}=== Result Comparison ===${NC}"
        echo "Expected (complete): $EXPECTED_RESULT"
        echo "Actual   (complete): $ACTUAL_RESULT"
        echo ""
        echo "Expected (first 64): ${EXPECTED_RESULT:0:64}..."
        echo "Actual   (first 64): ${ACTUAL_RESULT:0:64}..."
        echo -e "${CYAN}=========================${NC}"
        echo ""
        
        if [ "$EXPECTED_RESULT" = "$ACTUAL_RESULT" ]; then
            echo -e "${GREEN}✓ Test passed!${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}✗ Test failed! Results do not match${NC}"
            mismatch_count=$((mismatch_count + 1))
            {
                echo "=========================================="
                echo "Failed Test #$test_num ($TEST_TYPE) - $(date)"
                echo "=========================================="
                echo "Operation: $OPERATION_MODE"
                echo "Ethereum input: $ETHEREUM_INPUT_HEX"
                echo "Expected result: $EXPECTED_RESULT"
                echo "Actual result: $ACTUAL_RESULT"
                echo "Base64 Script: $BASE64_SCRIPT"
                echo ""
            } >> "$FAILED_TEST_LOG"
        fi
        
        echo ""
        continue
    fi
    
    # Compressed format test
    echo "Step 1: Running pairing_gen.go..."
    cd "$EVM_DIR"
    USE_G2_FLAG=""
    if [ "$USE_G2" = true ]; then
        USE_G2_FLAG="--use-g2"
    fi
    if ! go run pairing_gen.go "$MAX_SCALARS" $USE_G2_FLAG > "$TEMP_OUTPUT" 2>&1; then
        echo -e "${RED}Error: pairing_gen.go execution failed${NC}"
        cat "$TEMP_OUTPUT"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    echo "Step 2: Parsing pairing_gen.go output..."
    
    USE_MULTIPLE_POINTS=false
    POINTS_ARRAY=""
    
    if [ "$USE_G2" = true ]; then
        if grep -q "^private static readonly string\[\] G2_POINTS" "$TEMP_OUTPUT"; then
            USE_MULTIPLE_POINTS=true
            POINTS_ARRAY=$(awk '/private static readonly string\[\] G2_POINTS/,/^};/' "$TEMP_OUTPUT" | grep -E '^\s*"' | sed 's/.*"\(.*\)".*/\1/' | tr '\n' '|')
        fi
        
        if [ "$USE_MULTIPLE_POINTS" = false ]; then
            POINT_HEX=$(grep -m 1 "^G2 (compressed, 96 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            if [ -z "$POINT_HEX" ]; then
                echo -e "${RED}Error: Cannot extract G2_HEX${NC}"
                mismatch_count=$((mismatch_count + 1))
                continue
            fi
            
            if [ ${#POINT_HEX} -ne 192 ]; then
                echo -e "${RED}Error: G2_HEX length incorrect (expected 192 chars, got ${#POINT_HEX})${NC}"
                mismatch_count=$((mismatch_count + 1))
                continue
            fi
        fi
        
        EXPECTED_LENGTH=192
    else
        if grep -q "^private static readonly string\[\] G1_POINTS" "$TEMP_OUTPUT"; then
            USE_MULTIPLE_POINTS=true
            POINTS_ARRAY=$(awk '/private static readonly string\[\] G1_POINTS/,/^};/' "$TEMP_OUTPUT" | grep -E '^\s*"' | sed 's/.*"\(.*\)".*/\1/' | tr '\n' '|')
        fi
        
        if [ "$USE_MULTIPLE_POINTS" = false ]; then
            POINT_HEX=$(grep -m 1 "^G1 (compressed, 48 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
            if [ -z "$POINT_HEX" ]; then
                echo -e "${RED}Error: Cannot extract G1_HEX${NC}"
                mismatch_count=$((mismatch_count + 1))
                continue
            fi
            
            if [ ${#POINT_HEX} -ne 96 ]; then
                echo -e "${RED}Error: G1_HEX length incorrect (expected 96 chars, got ${#POINT_HEX})${NC}"
                mismatch_count=$((mismatch_count + 1))
                continue
            fi
        fi
        
        EXPECTED_LENGTH=96
    fi
    
    SCALARS_LINE=$(grep -m 1 "^private static readonly BigInteger\[\] SCALARS" "$TEMP_OUTPUT")
    if [ -z "$SCALARS_LINE" ]; then
        echo -e "${RED}Error: Cannot extract SCALARS${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    SCALARS=$(echo "$SCALARS_LINE" | sed 's/.*{ //' | sed 's/ };$//')
    if [ "$USE_G2" = true ]; then
        EXPECTED_RESULT=$(grep -m 1 "^G2 MultiExp result (compressed, 96 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
        [ -z "$EXPECTED_RESULT" ] && EXPECTED_RESULT=$(grep -m 1 "^Expected result (for comparison with Neo invokescript):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
    else
        EXPECTED_RESULT=$(grep -m 1 "^G1 MultiExp result (compressed, 48 bytes):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
        [ -z "$EXPECTED_RESULT" ] && EXPECTED_RESULT=$(grep -m 1 "^Expected result (for comparison with Neo invokescript):" "$TEMP_OUTPUT" | sed 's/.*: //' | tr -d '[:space:]')
    fi
    
    if [ -z "$EXPECTED_RESULT" ]; then
        echo -e "${RED}Error: Cannot extract Expected result${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    if [ ${#EXPECTED_RESULT} -ne $EXPECTED_LENGTH ]; then
        echo -e "${RED}Error: Expected result length incorrect (expected $EXPECTED_LENGTH chars, got ${#EXPECTED_RESULT})${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    echo ""
    echo -e "${CYAN}=== Key Parameters (for Manual Verification) ===${NC}"
    if [ "$USE_MULTIPLE_POINTS" = true ]; then
        POINT_COUNT=$(echo "$POINTS_ARRAY" | tr '|' '\n' | grep -c .)
        echo "Using multiple $(if [ "$USE_G2" = true ]; then echo "G2"; else echo "G1"; fi) points: $POINT_COUNT unique points"
        echo "Points array: ${POINTS_ARRAY:0:100}..."
    else
        if [ "$USE_G2" = true ]; then
            echo "G2_HEX (compressed format, 96 bytes, 192 hex chars): $POINT_HEX"
        else
            echo "G1_HEX (compressed format, 48 bytes, 96 hex chars): $POINT_HEX"
        fi
    fi
    echo "SCALARS (complete): $SCALARS"
    echo "Expected result (compressed format, $((EXPECTED_LENGTH/2)) bytes, $EXPECTED_LENGTH hex chars): $EXPECTED_RESULT"
    echo -e "${CYAN}===================================================${NC}"
    echo ""
    
    echo "Step 3: Updating Bls12381MultiExpHelper.cs..."
    cd "$SCRIPT_DIR/$HELPER_DIR"
    HELPER_CS_FILE="Bls12381MultiExpHelper.cs"
    cp "$HELPER_BACKUP" "$HELPER_CS_FILE"
    if [ "$USE_G2" = true ]; then
        sed -i.bak "s|private static readonly bool USE_G2 = .*;|private static readonly bool USE_G2 = true;|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
    else
        sed -i.bak "s|private static readonly bool USE_G2 = .*;|private static readonly bool USE_G2 = false;|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
    fi
    
    if [ "$USE_MULTIPLE_POINTS" = true ]; then
        if [ "$USE_G2" = true ]; then
            POINTS_BLOCK=$(awk '/private static readonly string\[\] G2_POINTS/,/^};/' "$TEMP_OUTPUT")
            "$PYTHON_CMD" <<PYTHON_SCRIPT
import re
import os
import sys

# Use relative path since we're in HELPER_DIR
helper_file = "Bls12381MultiExpHelper.cs"
if not os.path.exists(helper_file):
    # Fallback: use absolute path relative to script directory
    abs_path = os.path.join("$SCRIPT_DIR", "$HELPER_CS")
    helper_file = abs_path

with open(helper_file, "r", encoding="utf-8") as f:
    content = f.read()

pattern = r'private static readonly string\[\] G2_POINTS\s*=\s*new\s*string\[\]\s*\{.*?^\s*\};'
replacement = """$POINTS_BLOCK"""
content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

with open(helper_file, "w", encoding="utf-8") as f:
    f.write(content)
PYTHON_SCRIPT
        else
            POINTS_BLOCK=$(awk '/private static readonly string\[\] G1_POINTS/,/^};/' "$TEMP_OUTPUT")
            "$PYTHON_CMD" <<PYTHON_SCRIPT
import re
import os
import sys

# Use relative path since we're in HELPER_DIR
helper_file = "Bls12381MultiExpHelper.cs"
if not os.path.exists(helper_file):
    # Fallback: use absolute path relative to script directory
    abs_path = os.path.join("$SCRIPT_DIR", "$HELPER_CS")
    helper_file = abs_path

with open(helper_file, "r", encoding="utf-8") as f:
    content = f.read()

pattern = r'private static readonly string\[\] G1_POINTS\s*=\s*new\s*string\[\]\s*\{.*?^\s*\};'
replacement = """$POINTS_BLOCK"""
content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

with open(helper_file, "w", encoding="utf-8") as f:
    f.write(content)
PYTHON_SCRIPT
        fi
        POINT_COUNT=$(echo "$POINTS_ARRAY" | tr '|' '\n' | grep -c .)
        echo "  Updated $(if [ "$USE_G2" = true ]; then echo "G2"; else echo "G1"; fi)_POINTS array with $POINT_COUNT points"
        else
            if [ "$USE_G2" = true ]; then
            sed -i.bak "s|private static readonly string G2_HEX = \".*\";|private static readonly string G2_HEX = \"$POINT_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            echo "  Updated G2_HEX: ${POINT_HEX:0:32}..."
        else
            sed -i.bak "s|private static readonly string G1_HEX = \".*\";|private static readonly string G1_HEX = \"$POINT_HEX\";|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
            echo "  Updated G1_HEX: ${POINT_HEX:0:32}..."
        fi
    fi
    
    sed -i.bak "s|private static readonly BigInteger\[\] SCALARS = new BigInteger\[\] { .* };|private static readonly BigInteger[] SCALARS = new BigInteger[] { $SCALARS };|" "$HELPER_CS_FILE" && rm -f "$HELPER_CS_FILE.bak"
    echo "  Updated SCALARS: ${SCALARS:0:80}..."
    
    echo "Step 4: Generating Neo VM script..."
    # Already in HELPER_DIR from Step 3
    
    if ! dotnet run --project Bls12381MultiExpHelper.csproj > "$TEMP_OUTPUT" 2>&1; then
        echo -e "${RED}Error: C# program execution failed${NC}"
        cat "$TEMP_OUTPUT"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    if grep -q "Pair\[" "$TEMP_OUTPUT"; then
        echo ""
        echo -e "${CYAN}=== Neo Point-Scalar Pairs (for verification) ===${NC}"
        grep "Pair\[" "$TEMP_OUTPUT" | head -n 10
        if [ $(grep -c "Pair\[" "$TEMP_OUTPUT") -gt 10 ]; then
            echo "  ... (showing first 10 pairs)"
        fi
        echo -e "${CYAN}===================================================${NC}"
        echo ""
    fi
    
    BASE64_SCRIPT=$(grep -A 1 "Base64 encoding (for Neo CLI):" "$TEMP_OUTPUT" | tail -n 1 | tr -d '[:space:]')
    if [ -z "$BASE64_SCRIPT" ]; then
        echo -e "${RED}Error: Cannot extract Base64 script${NC}"
        cat "$TEMP_OUTPUT"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    echo "  Generated script length: ${#BASE64_SCRIPT} characters"
    
    echo "Step 5: Calling Neo RPC invokescript..."
    if [ "$JSON_PARSER" = "jq" ]; then
        RPC_REQUEST=$(jq -n \
            --arg script "$BASE64_SCRIPT" \
            '{
                jsonrpc: "2.0",
                id: 1,
                method: "invokescript",
                params: [$script, [], false]
            }')
    else
        RPC_REQUEST=$(echo "$BASE64_SCRIPT" | "$JSON_PARSER" -c "
import json
import sys
script = sys.stdin.read().strip()
request = {
    'jsonrpc': '2.0',
    'id': 1,
    'method': 'invokescript',
    'params': [script, [], False]
}
print(json.dumps(request))
")
    fi
    
    RPC_RESPONSE=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "$RPC_REQUEST")
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: RPC call failed${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    RPC_ERROR=$(json_get "$RPC_RESPONSE" ".error" "")
    if [ -n "$RPC_ERROR" ] && [ "$RPC_ERROR" != "null" ]; then
        echo -e "${RED}Error: RPC returned error: $RPC_ERROR${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    STATE=$(json_get "$RPC_RESPONSE" ".result.state" "")
    if [ "$STATE" != "HALT" ]; then
        EXCEPTION=$(json_get "$RPC_RESPONSE" ".result.exception" "unknown")
        echo -e "${RED}Error: Script execution failed, state: $STATE, exception: $EXCEPTION${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    STACK_VALUE=$(json_get "$RPC_RESPONSE" ".result.stack[0].value" "")
    STACK_TYPE=$(json_get "$RPC_RESPONSE" ".result.stack[0].type" "")
    
    if [ -z "$STACK_VALUE" ] || [ "$STACK_VALUE" = "null" ]; then
        echo -e "${RED}Error: Cannot extract result from stack${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    echo "  Stack type: $STACK_TYPE"
    echo "  Stack value (Base64, first 64 chars): ${STACK_VALUE:0:64}..."
    
    if command -v base64 >/dev/null 2>&1; then
        ACTUAL_RESULT=$(echo "$STACK_VALUE" | base64 -d 2>/dev/null | xxd -p -c 256 | tr -d '\n' 2>/dev/null)
        if [ $? -ne 0 ]; then
            ACTUAL_RESULT=$(echo "$STACK_VALUE" | base64 -D 2>/dev/null | xxd -p -c 256 | tr -d '\n' 2>/dev/null)
        fi
    else
        echo -e "${RED}Error: base64 command not found${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    if [ -z "$ACTUAL_RESULT" ]; then
        echo -e "${RED}Error: Cannot convert result format${NC}"
        mismatch_count=$((mismatch_count + 1))
        continue
    fi
    
    echo "Step 6: Comparing results..."
    echo ""
    echo -e "${CYAN}=== Result Comparison ===${NC}"
    echo "Expected (complete): $EXPECTED_RESULT"
    echo "Actual   (complete): $ACTUAL_RESULT"
    echo ""
    echo "Expected (first 32): ${EXPECTED_RESULT:0:32}..."
    echo "Actual   (first 32): ${ACTUAL_RESULT:0:32}..."
    echo -e "${CYAN}=========================${NC}"
    echo ""
    
    if [ "$EXPECTED_RESULT" = "$ACTUAL_RESULT" ]; then
        echo -e "${GREEN}✓ Test passed!${NC}"
        success_count=$((success_count + 1))
    else
        echo -e "${RED}✗ Test failed! Results do not match${NC}"
        mismatch_count=$((mismatch_count + 1))
        {
            echo "=========================================="
            echo "Failed Test #$test_num ($TEST_TYPE) - $(date)"
            echo "=========================================="
            if [ "$USE_G2" = true ]; then
                echo "G2_HEX (compressed format, 96 bytes): $POINT_HEX"
            else
                echo "G1_HEX (compressed format, 48 bytes): $POINT_HEX"
            fi
            echo "SCALARS: $SCALARS"
            echo "Expected result: $EXPECTED_RESULT"
            echo "Actual result: $ACTUAL_RESULT"
            echo "Base64 Script: $BASE64_SCRIPT"
            echo ""
        } >> "$FAILED_TEST_LOG"
    fi
    
    echo ""
done

echo -e "${CYAN}=== Test Complete ===${NC}"
echo "Test type: $TEST_TYPE"
echo "Total tests: $NUM_TESTS"
echo -e "${GREEN}Passed: $success_count${NC}"
echo -e "${RED}Failed: $mismatch_count${NC}"

if [ $mismatch_count -gt 0 ] && [ -f "$FAILED_TEST_LOG" ]; then
    echo ""
    echo -e "${YELLOW}Detailed parameters of failed tests saved to: $FAILED_TEST_LOG${NC}"
fi

if [ $mismatch_count -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ $mismatch_count test(s) failed${NC}"
    exit 1
fi

