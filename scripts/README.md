# Python Helper Scripts

这些 Python 脚本用于 `test_bls12381_multiexp_enhanced.sh` 中更新 `Bls12381MultiExpHelper.cs` 文件。

## 脚本列表

### 1. `update_pairing_arrays.py`

更新 `G1_PAIRS` 和 `G2_PAIRS` 数组（从空格分隔的点列表）。

**用法：**
```bash
python update_pairing_arrays.py <helper_file> <g1_pairs_list> <g2_pairs_list>
```

**参数：**
- `helper_file`: `Bls12381MultiExpHelper.cs` 文件路径
- `g1_pairs_list`: 空格分隔的 G1 点列表（例如："point1 point2 point3"）
- `g2_pairs_list`: 空格分隔的 G2 点列表（例如："point1 point2 point3"）

**示例：**
```bash
python update_pairing_arrays.py Bls12381MultiExpHelper.cs "abc123 def456" "xyz789 uvw012"
```

### 2. `update_pairing_arrays_from_block.py`

从代码块更新 `G1_PAIRS` 和 `G2_PAIRS` 数组（从 `pairing_gen.go` 的输出）。

**用法：**
```bash
python update_pairing_arrays_from_block.py <helper_file> <g1_pairs_block> <g2_pairs_block>
```

**参数：**
- `helper_file`: `Bls12381MultiExpHelper.cs` 文件路径
- `g1_pairs_block`: G1_PAIRS 数组的代码块（可以是文件路径或直接内容）
- `g2_pairs_block`: G2_PAIRS 数组的代码块（可以是文件路径或直接内容）

**示例：**
```bash
# 使用文件
python update_pairing_arrays_from_block.py Bls12381MultiExpHelper.cs g1_block.txt g2_block.txt

# 或直接传递内容（通过临时文件）
python update_pairing_arrays_from_block.py Bls12381MultiExpHelper.cs "$G1_BLOCK_TEMP" "$G2_BLOCK_TEMP"
```

### 3. `update_points_array.py`

更新 `G1_POINTS` 或 `G2_POINTS` 数组（从代码块）。

**用法：**
```bash
python update_points_array.py <helper_file> <points_block> [--g2]
```

**参数：**
- `helper_file`: `Bls12381MultiExpHelper.cs` 文件路径
- `points_block`: POINTS 数组的代码块（可以是文件路径或直接内容）
- `--g2`: 可选标志，如果提供则更新 `G2_POINTS`，否则更新 `G1_POINTS`

**示例：**
```bash
# 更新 G1_POINTS
python update_points_array.py Bls12381MultiExpHelper.cs points_block.txt

# 更新 G2_POINTS
python update_points_array.py Bls12381MultiExpHelper.cs points_block.txt --g2
```

## 注意事项

- 所有脚本都支持 UTF-8 编码
- 脚本会自动处理文件路径的解析（支持相对路径和绝对路径）
- 对于多行内容，建议使用临时文件传递（脚本会自动检测是否为文件路径）
- 所有脚本在成功时返回 0，失败时返回非零值

## 依赖

- Python 3.x
- 标准库：`re`, `os`, `sys`

