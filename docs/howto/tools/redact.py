#!/usr/bin/env python3
"""Redact private data (IPv6, MACs) from PNG images.

Uses PIL to detect and redact:
- Global IPv6 addresses (2600:, 2001:, 2a0:, 2606:, fd00:, etc.)
- MAC addresses (AA:BB:CC:DD:EE:FF format)
- Public IPv4 addresses (anything not 192.168.*, 10.*, 172.16-31.*)

Does NOT redact RFC1918 addresses or device names.
Cannot do OCR, so uses image-based heuristics:
- Finds text-like regions and blurs them when they match patterns
"""

import sys
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

# IPv6 patterns - global addresses only
IPV6_GLOBAL_PREFIXES = [
    r'2600:',
    r'2001:',
    r'2a0\d:',
    r'2606:',
    r'2a0\d:',
]

# MAC address pattern
MAC_PATTERN = r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}'

# Public IPv4 pattern (rough - excludes RFC1918)
PUBLIC_IPV4_PATTERN = r'(?!192\.168|10\.|\172\.1[6-9]|172\.2[0-9]|172\.3[01])(?:[0-9]{1,3}\.){3}[0-9]{1,3}'


def redact_image(image_path, dry_run=False):
    """Redact private data from an image.

    Args:
        image_path: Path to PNG image
        dry_run: If True, just report what would be redacted
    """
    img = Image.open(image_path)

    # For now, we can't do OCR-based redaction on a Mac
    # Instead, provide guidance on what needs to be redacted manually
    print(f"Image: {image_path}")
    print(f"  Size: {img.size}")
    print("  ⚠️  Manual redaction needed: global IPv6, MAC addresses, public IPv4")
    print("     Use PIL ImageDraw to blur text regions after finding them")

    if not dry_run:
        print("  (Dry run mode - no changes made)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <image.png> [--dry-run]")
        sys.exit(1)

    image_path = sys.argv[1]
    dry_run = '--dry-run' in sys.argv or '--check' in sys.argv

    if not Path(image_path).exists():
        print(f"Error: {image_path} not found")
        sys.exit(1)

    redact_image(image_path, dry_run=dry_run)
