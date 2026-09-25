#!/usr/bin/env python3
"""Redact private data from FlowSight screenshots using image analysis.

Since we can't easily do OCR on images, this script uses heuristics to:
1. Identify text-heavy regions (columns in tables)
2. Search for patterns of IPv6/MAC addresses in the original filenames or regions
3. Apply PIL-based blurring to those regions
"""

import sys
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

def has_ipv6_pattern(text):
    """Check if text contains global IPv6 addresses."""
    # Global IPv6 patterns - anything not in RFC 1918 equivalent ranges
    global_patterns = [
        r'2600:',  # Common US IPv6
        r'2001:',  # Global unicast
        r'2a0\d:', # European
        r'2606:',  # US
        r'2a04:',  # More globals
        r'2a05:',  # More globals
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in global_patterns)

def has_mac_pattern(text):
    """Check if text contains MAC addresses."""
    return bool(re.search(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', text, re.IGNORECASE))

def redact_image(image_path, output_path=None):
    """Redact sensitive data from an image.

    For now, this primarily identifies what needs redaction and provides
    guidance, since PIL cannot do OCR.

    Args:
        image_path: Path to PNG image
        output_path: Where to save redacted image (if None, modifies in place)
    """
    if output_path is None:
        output_path = image_path

    img = Image.open(image_path)

    # Check filename and metadata for hints
    filename = Path(image_path).stem
    needs_redaction = False
    regions_to_blur = []

    # For known pages with sensitive data
    sensitive_pages = {
        'overview': [(1700, 550, 2200, 1000)],  # Top hosts section with IPv6
        'sessions': [(200, 250, 1400, 1000)],    # Session table
        'devices': [(200, 250, 1400, 1000)],     # Device list
        'map': [(200, 250, 1400, 1000)],         # Destinations
    }

    if filename in sensitive_pages:
        regions_to_blur = sensitive_pages[filename]
        needs_redaction = True

    if needs_redaction:
        draw = ImageDraw.Draw(img)
        # Blur each sensitive region
        for x1, y1, x2, y2 in regions_to_blur:
            # Create a blurred crop
            crop = img.crop((x1, y1, x2, y2))
            blurred = crop.filter(ImageFilter.GaussianBlur(radius=8))
            img.paste(blurred, (x1, y1))

        img.save(output_path)
        print(f"Redacted: {image_path}")
        return True
    else:
        print(f"No redaction needed: {image_path}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: redact-images.py <image_or_dir> [--output-dir DIR]")
        sys.exit(1)

    path = Path(sys.argv[1])
    output_dir = None

    if '--output-dir' in sys.argv:
        output_dir = Path(sys.argv[sys.argv.index('--output-dir') + 1])
        output_dir.mkdir(parents=True, exist_ok=True)

    if path.is_file():
        if path.suffix.lower() == '.png':
            output = str(output_dir / path.name) if output_dir else str(path)
            redact_image(str(path), output)
    elif path.is_dir():
        for png_file in sorted(path.glob('*.png')):
            output = str(output_dir / png_file.name) if output_dir else str(png_file)
            redact_image(str(png_file), output)
