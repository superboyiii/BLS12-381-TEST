#!/usr/bin/env python3
"""
Update G1_PAIRS and G2_PAIRS arrays in Bls12381MultiExpHelper.cs
from space-separated lists of points.
"""

import re
import os
import sys


def update_pairing_arrays(helper_file, g1_pairs_list, g2_pairs_list):
    """
    Update G1_PAIRS and G2_PAIRS arrays in the helper file.
    
    Args:
        helper_file: Path to Bls12381MultiExpHelper.cs
        g1_pairs_list: Space-separated string of G1 points
        g2_pairs_list: Space-separated string of G2 points
    """
    if not os.path.exists(helper_file):
        print(f"Error: File not found: {helper_file}", file=sys.stderr)
        return 1
    
    with open(helper_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Build G1_PAIRS array
    g1_pairs = [p.strip() for p in g1_pairs_list.split() if p.strip()]
    g1_pairs_str = "private static readonly string[] G1_PAIRS = new string[]\n{\n"
    for i, pair in enumerate(g1_pairs):
        g1_pairs_str += f'    "{pair}"'
        if i < len(g1_pairs) - 1:
            g1_pairs_str += ","
        g1_pairs_str += "\n"
    g1_pairs_str += "};"
    
    # Build G2_PAIRS array
    g2_pairs = [p.strip() for p in g2_pairs_list.split() if p.strip()]
    g2_pairs_str = "private static readonly string[] G2_PAIRS = new string[]\n{\n"
    for i, pair in enumerate(g2_pairs):
        g2_pairs_str += f'    "{pair}"'
        if i < len(g2_pairs) - 1:
            g2_pairs_str += ","
        g2_pairs_str += "\n"
    g2_pairs_str += "};"
    
    # Replace G1_PAIRS
    pattern_g1 = r'private static readonly string\[\] G1_PAIRS\s*=\s*.*?;'
    content = re.sub(pattern_g1, g1_pairs_str, content, flags=re.MULTILINE | re.DOTALL)
    
    # Replace G2_PAIRS
    pattern_g2 = r'private static readonly string\[\] G2_PAIRS\s*=\s*.*?;'
    content = re.sub(pattern_g2, g2_pairs_str, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(helper_file, "w", encoding="utf-8") as f:
        f.write(content)
    
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: update_pairing_arrays.py <helper_file> <g1_pairs_list> <g2_pairs_list>", file=sys.stderr)
        sys.exit(1)
    
    helper_file = sys.argv[1]
    g1_pairs_list = sys.argv[2]
    g2_pairs_list = sys.argv[3]
    
    sys.exit(update_pairing_arrays(helper_file, g1_pairs_list, g2_pairs_list))

