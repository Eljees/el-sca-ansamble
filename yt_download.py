import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_yt_dlp():
    found = shutil.which("yt-dlp") or shutil.which("yt-dlp.exe")
    if found:
        return found
    candidates = [
        Path(sys.executable).parent / "Scripts" / "yt-dlp.exe",
        Path(sys.executable).parent / "yt-dlp.exe",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        roaming = Path(appdata) / "Python"
        if roaming.exists():
            for d in roaming.iterdir():
                candidates.append(d / "Scripts" / "yt-dlp.exe")
    for c in candidates:
        if c.exists():
            return str(c)
    return ""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("url", nargs="?", default="https://www.youtube.com/watch?v=Jkixh8Jgn_4")
    p.add_argument("-q", "--quality", default="best")
    p.add_argument("-o", "--output", default=".")
    p.add_argument("-a", "--audio", action="store_true")
    p.add_argument("-b", "--browser", default="firefox")
    args = p.parse_args()

    yt = find_yt_dlp()
    if not yt:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", "yt-dlp"], check=True)
        yt = find_yt_dlp()

    cmd = [yt, "-o", f"{args.output}/%(title)s.%(ext)s"]
    if args.audio:
        cmd += ["-x", "--audio-format", "mp3"]
    else:
        q = args.quality
        fmt = (
            "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best"
            if q == "best"
            else f"bestvideo[height<={q}][ext=mp4]+bestaudio[ext=m4a]/best[height<={q}]"
        )
        cmd += ["-f", fmt, "--merge-output-format", "mp4"]
    if args.browser != "none":
        cmd += ["--cookies-from-browser", args.browser]
    cmd += ["--add-metadata", args.url]

    print(f"Скачиваю: {args.url}")
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
