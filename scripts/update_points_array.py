#!/usr/bin/env python3
"""
Update G1_POINTS or G2_POINTS array in Bls12381MultiExpHelper.cs
from a code block (as output from pairing_gen.go).
"""

import re
import os
import sys


def update_points_array(helper_file, points_block, use_g2=False):
    """
    Update G1_POINTS or G2_POINTS array in the helper file from a code block.
    
    Args:
        helper_file: Path to Bls12381MultiExpHelper.cs
        points_block: Code block for POINTS array (from pairing_gen.go)
        use_g2: If True, update G2_POINTS; otherwise update G1_POINTS
    """
    if not os.path.exists(helper_file):
        print(f"Error: File not found: {helper_file}", file=sys.stderr)
        return 1
    
    with open(helper_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    if use_g2:
        pattern = r'private static readonly string\[\] G2_POINTS\s*=\s*new\s*string\[\]\s*\{.*?^\s*\};'
    else:
        pattern = r'private static readonly string\[\] G1_POINTS\s*=\s*new\s*string\[\]\s*\{.*?^\s*\};'
    
    content = re.sub(pattern, points_block, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(helper_file, "w", encoding="utf-8") as f:
        f.write(content)
    
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: update_points_array.py <helper_file> <points_block_file> [--g2]", file=sys.stderr)
        print("       or: update_points_array.py <helper_file> <points_block> [--g2]", file=sys.stderr)
        sys.exit(1)
    
    helper_file = sys.argv[1]
    points_block_arg = sys.argv[2]
    use_g2 = "--g2" in sys.argv
    
    # Check if argument is a file path or actual content
    if os.path.isfile(points_block_arg):
        with open(points_block_arg, "r", encoding="utf-8") as f:
            points_block = f.read()
    else:
        points_block = points_block_arg
    
    sys.exit(update_points_array(helper_file, points_block, use_g2))

