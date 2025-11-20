#!/usr/bin/env python3
"""
Update G1_PAIRS and G2_PAIRS arrays in Bls12381MultiExpHelper.cs
from code blocks (as output from pairing_gen.go).
"""

import re
import os
import sys


def update_pairing_arrays_from_block(helper_file, g1_pairs_block, g2_pairs_block):
    """
    Update G1_PAIRS and G2_PAIRS arrays in the helper file from code blocks.
    
    Args:
        helper_file: Path to Bls12381MultiExpHelper.cs
        g1_pairs_block: Code block for G1_PAIRS array (from pairing_gen.go)
        g2_pairs_block: Code block for G2_PAIRS array (from pairing_gen.go)
    """
    if not os.path.exists(helper_file):
        print(f"Error: File not found: {helper_file}", file=sys.stderr)
        return 1
    
    with open(helper_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Replace G1_PAIRS array
    # Pattern needs to match: private static readonly string[] G1_PAIRS = Array.Empty<string>();
    # or: private static readonly string[] G1_PAIRS = new string[] { ... };
    pattern_g1 = r'private static readonly string\[\] G1_PAIRS\s*=\s*.*?;'
    g1_replacement = g1_pairs_block.rstrip()
    # Ensure it ends with semicolon
    if not g1_replacement.rstrip().endswith(';'):
        g1_replacement += ';'
    # Replace using DOTALL to match across newlines
    content = re.sub(pattern_g1, g1_replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    # Replace G2_PAIRS array
    pattern_g2 = r'private static readonly string\[\] G2_PAIRS\s*=\s*.*?;'
    g2_replacement = g2_pairs_block.rstrip()
    if not g2_replacement.rstrip().endswith(';'):
        g2_replacement += ';'
    content = re.sub(pattern_g2, g2_replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(helper_file, "w", encoding="utf-8") as f:
        f.write(content)
    
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: update_pairing_arrays_from_block.py <helper_file> <g1_pairs_block_file> <g2_pairs_block_file>", file=sys.stderr)
        print("       or: update_pairing_arrays_from_block.py <helper_file> <g1_pairs_block> <g2_pairs_block>", file=sys.stderr)
        sys.exit(1)
    
    helper_file = sys.argv[1]
    g1_pairs_block_arg = sys.argv[2]
    g2_pairs_block_arg = sys.argv[3]
    
    # Check if arguments are file paths or actual content
    # If they look like file paths (contain newlines or are very long), read from file
    # Otherwise, treat as direct content
    if os.path.isfile(g1_pairs_block_arg):
        with open(g1_pairs_block_arg, "r", encoding="utf-8") as f:
            g1_pairs_block = f.read()
    else:
        g1_pairs_block = g1_pairs_block_arg
    
    if os.path.isfile(g2_pairs_block_arg):
        with open(g2_pairs_block_arg, "r", encoding="utf-8") as f:
            g2_pairs_block = f.read()
    else:
        g2_pairs_block = g2_pairs_block_arg
    
    sys.exit(update_pairing_arrays_from_block(helper_file, g1_pairs_block, g2_pairs_block))

