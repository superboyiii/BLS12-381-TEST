# Python Helper Scripts

These Python utilities keep `Bls12381MultiExpHelper.cs` in sync with the datasets
produced by `test_bls12381_multiexp_enhanced.sh` (and therefore by
`pairing_gen.go`).

## Script Overview

### 1. `update_pairing_arrays.py`

Populate `G1_PAIRS` and `G2_PAIRS` from **space–separated** point lists.

**Usage**
```bash
python update_pairing_arrays.py <helper_file> <g1_pairs_list> <g2_pairs_list>
```

**Arguments**
- `helper_file`: path to `Bls12381MultiExpHelper.cs`
- `g1_pairs_list`: space-delimited G1 entries (for example `"p1 p2 p3"`)
- `g2_pairs_list`: space-delimited G2 entries

**Example**
```bash
python update_pairing_arrays.py Bls12381MultiExpHelper.cs "abc123 def456" "xyz789 uvw012"
```

### 2. `update_pairing_arrays_from_block.py`

Update `G1_PAIRS` and `G2_PAIRS` using **verbatim code blocks** (typically copied
from `pairing_gen.go` output).

**Usage**
```bash
python update_pairing_arrays_from_block.py <helper_file> <g1_pairs_block> <g2_pairs_block>
```

**Arguments**
- `helper_file`: path to `Bls12381MultiExpHelper.cs`
- `g1_pairs_block`: block for `G1_PAIRS` (file path or raw content)
- `g2_pairs_block`: block for `G2_PAIRS` (file path or raw content)

**Example**
```bash
# Using intermediate files
python update_pairing_arrays_from_block.py Bls12381MultiExpHelper.cs g1_block.txt g2_block.txt

# Passing inline content (for example via temp files)
python update_pairing_arrays_from_block.py Bls12381MultiExpHelper.cs "$G1_BLOCK_TEMP" "$G2_BLOCK_TEMP"
```

### 3. `update_points_array.py`

Refresh `G1_POINTS` or `G2_POINTS` from a code block.

**Usage**
```bash
python update_points_array.py <helper_file> <points_block> [--g2]
```

**Arguments**
- `helper_file`: path to `Bls12381MultiExpHelper.cs`
- `points_block`: block describing the array (file path or raw content)
- `--g2`: optional flag; when present the script updates `G2_POINTS`, otherwise
  it targets `G1_POINTS`

**Example**
```bash
# Update G1_POINTS
python update_points_array.py Bls12381MultiExpHelper.cs points_block.txt

# Update G2_POINTS
python update_points_array.py Bls12381MultiExpHelper.cs points_block.txt --g2
```

## Notes

- All scripts assume UTF-8 input/output.
- Both absolute and relative paths are accepted; the helper automatically
  detects whether an argument is a path or inline content.
- For multi-line payloads, using temporary files is recommended but not
  required.
- Exit code `0` indicates success; any non-zero value means the update failed.

## Requirements

- Python 3.x
- Standard library only (`re`, `os`, `sys`)

