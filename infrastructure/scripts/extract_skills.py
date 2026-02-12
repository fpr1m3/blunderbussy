#!/usr/bin/env python3
"""
Skill Extraction Pipeline for Dame

Extracts attack skills from hacking tutorial videos using fabric.
Handles multiple playlists, deduplication, and generates an index report.

Usage:
    python extract_skills.py --playlists playlists.txt --output ./skills_corpus
    python extract_skills.py --video "https://youtube.com/watch?v=..." --output ./skills_corpus
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kwargs):
        return iterable


@dataclass
class VideoMeta:
    video_id: str
    title: str
    playlist_id: Optional[str] = None
    playlist_title: Optional[str] = None
    skill_count: int = 0
    processed: bool = False
    error: Optional[str] = None


class SkillExtractor:
    def __init__(self, output_dir: Path, fabric_pattern: str = "fp_extract_hack_skills",
                 rate_limit: float = 2.0, fabric_path: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.videos_dir = self.output_dir / "videos"
        self.fabric_pattern = fabric_pattern
        self.rate_limit = rate_limit
        self.fabric_path = fabric_path or shutil.which("fabric") or "fabric"

        # State files
        self.metadata_file = self.output_dir / "metadata.json"
        self.processed_file = self.output_dir / "processed.txt"
        self.index_file = self.output_dir / "index.md"
        self.combined_file = self.output_dir / "all_skills.jsonl"

        # In-memory state
        self.metadata: dict[str, VideoMeta] = {}
        self.processed_ids: set[str] = set()

        self._setup_dirs()
        self._load_state()

    def _setup_dirs(self):
        """Create output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.videos_dir.mkdir(exist_ok=True)

    def _load_state(self):
        """Load existing state for resume support."""
        if self.processed_file.exists():
            self.processed_ids = set(self.processed_file.read_text().strip().split('\n'))
            self.processed_ids.discard('')  # Remove empty strings

        if self.metadata_file.exists():
            raw = json.loads(self.metadata_file.read_text())
            self.metadata = {k: VideoMeta(**v) for k, v in raw.items()}

    def _save_state(self):
        """Persist state to disk."""
        self.processed_file.write_text('\n'.join(sorted(self.processed_ids)))

        raw = {k: asdict(v) for k, v in self.metadata.items()}
        self.metadata_file.write_text(json.dumps(raw, indent=2))

    def get_playlist_videos(self, playlist_url: str) -> list[VideoMeta]:
        """Fetch video IDs and titles from a playlist."""
        print(f"  Fetching playlist: {playlist_url}")

        cmd = [
            "yt-dlp", "--flat-playlist", "--print", "%(id)s\t%(title)s",
            "--print", "playlist_id:%(playlist_id)s", "--print", "playlist_title:%(playlist_title)s",
            playlist_url
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                print(f"    Warning: yt-dlp error: {result.stderr[:200]}")
                return []
        except subprocess.TimeoutExpired:
            print(f"    Warning: yt-dlp timeout for {playlist_url}")
            return []

        videos = []
        playlist_id = None
        playlist_title = None

        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            if line.startswith('playlist_id:'):
                playlist_id = line.split(':', 1)[1]
            elif line.startswith('playlist_title:'):
                playlist_title = line.split(':', 1)[1]
            elif '\t' in line:
                video_id, title = line.split('\t', 1)
                videos.append(VideoMeta(
                    video_id=video_id,
                    title=title,
                    playlist_id=playlist_id,
                    playlist_title=playlist_title
                ))

        print(f"    Found {len(videos)} videos")
        return videos

    def get_single_video(self, video_url: str) -> Optional[VideoMeta]:
        """Fetch metadata for a single video."""
        # Extract video ID from URL
        match = re.search(r'(?:v=|/)([a-zA-Z0-9_-]{11})', video_url)
        if not match:
            print(f"  Could not extract video ID from: {video_url}")
            return None

        video_id = match.group(1)

        cmd = ["yt-dlp", "--print", "%(title)s", "--skip-download", video_url]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            title = result.stdout.strip() or f"Unknown ({video_id})"
        except:
            title = f"Unknown ({video_id})"

        return VideoMeta(video_id=video_id, title=title)

    def extract_skills(self, video: VideoMeta) -> tuple[int, Optional[str]]:
        """Extract skills from a video using fabric."""
        url = f"https://www.youtube.com/watch?v={video.video_id}"
        output_file = self.videos_dir / f"{video.video_id}.jsonl"

        cmd = [
            self.fabric_path,
            "-y", url,
            "-p", self.fabric_pattern,
            "-o", str(output_file)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0 or not output_file.exists():
                return 0, f"fabric error: {result.stderr[:200]}"

            # Post-process: fix escaped dollar signs
            content = output_file.read_text()
            fixed_content = content.replace('\\$', '$')
            output_file.write_text(fixed_content)

            # Count valid JSON lines
            skill_count = 0
            for line in fixed_content.strip().split('\n'):
                if line.strip():
                    try:
                        json.loads(line)
                        skill_count += 1
                    except json.JSONDecodeError:
                        pass

            return skill_count, None

        except subprocess.TimeoutExpired:
            return 0, "fabric timeout (5min)"
        except Exception as e:
            return 0, str(e)

    def process_playlists(self, playlist_file: Path):
        """Process all playlists from a file."""
        if not playlist_file.exists():
            print(f"Error: Playlist file not found: {playlist_file}")
            sys.exit(1)

        playlist_urls = [
            line.strip() for line in playlist_file.read_text().split('\n')
            if line.strip() and not line.startswith('#')
        ]

        print(f"Loading {len(playlist_urls)} playlists...")

        # Collect all videos, tracking first occurrence
        all_videos: dict[str, VideoMeta] = {}
        duplicates = 0

        for url in playlist_urls:
            videos = self.get_playlist_videos(url)
            for video in videos:
                if video.video_id not in all_videos:
                    all_videos[video.video_id] = video
                else:
                    duplicates += 1

        print(f"\nTotal unique videos: {len(all_videos)}")
        print(f"Duplicates skipped: {duplicates}")
        print(f"Already processed: {len(self.processed_ids & set(all_videos.keys()))}")

        # Filter to unprocessed
        to_process = [v for v in all_videos.values() if v.video_id not in self.processed_ids]
        print(f"Videos to process: {len(to_process)}\n")

        if not to_process:
            print("Nothing to process!")
            self._generate_index()
            return

        self._process_videos(to_process)

    def process_single_video(self, video_url: str):
        """Process a single video."""
        video = self.get_single_video(video_url)
        if not video:
            return

        if video.video_id in self.processed_ids:
            print(f"Video already processed: {video.video_id}")
            self._generate_index()
            return

        self._process_videos([video])

    def _process_videos(self, videos: list[VideoMeta]):
        """Process a list of videos."""
        iterator = tqdm(videos, desc="Extracting skills") if HAS_TQDM else videos

        for video in iterator:
            if not HAS_TQDM:
                print(f"Processing [{video.video_id}] {video.title[:50]}...")

            skill_count, error = self.extract_skills(video)

            video.skill_count = skill_count
            video.processed = error is None
            video.error = error

            self.metadata[video.video_id] = video

            if video.processed:
                self.processed_ids.add(video.video_id)

            # Save state after each video (resume support)
            self._save_state()

            if not HAS_TQDM:
                status = f"  → {skill_count} skills" if video.processed else f"  → ERROR: {error}"
                print(status)

            time.sleep(self.rate_limit)

        # Generate outputs
        self._combine_skills()
        self._generate_index()

    def _combine_skills(self):
        """Combine all skill files into one."""
        print("\nCombining skill files...")

        with open(self.combined_file, 'w') as out:
            for jsonl_file in sorted(self.videos_dir.glob('*.jsonl')):
                for line in jsonl_file.read_text().strip().split('\n'):
                    if line.strip():
                        try:
                            # Validate JSON and add source
                            skill = json.loads(line)
                            skill['_source_video'] = jsonl_file.stem
                            out.write(json.dumps(skill) + '\n')
                        except json.JSONDecodeError:
                            pass

        total = sum(1 for _ in open(self.combined_file))
        print(f"Combined {total} skills into {self.combined_file}")

    def _generate_index(self):
        """Generate the markdown index/homepage."""
        print("Generating index.md...")

        # Sort by title
        sorted_videos = sorted(self.metadata.values(), key=lambda v: v.title.lower())

        # Stats
        total_videos = len(sorted_videos)
        processed_videos = sum(1 for v in sorted_videos if v.processed)
        failed_videos = sum(1 for v in sorted_videos if v.error)
        total_skills = sum(v.skill_count for v in sorted_videos)

        lines = [
            "# Skill Extraction Corpus",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Statistics",
            "",
            f"- **Total Videos:** {total_videos}",
            f"- **Successfully Processed:** {processed_videos}",
            f"- **Failed:** {failed_videos}",
            f"- **Total Skills Extracted:** {total_skills}",
            "",
            "## Videos",
            "",
            "| Video ID | Title | Skills | Status |",
            "|----------|-------|--------|--------|",
        ]

        for video in sorted_videos:
            video_id = video.video_id
            title = video.title.replace('|', '\\|')[:60]
            yt_link = f"[{video_id}](https://youtube.com/watch?v={video_id})"

            if video.processed:
                skill_link = f"[{video.skill_count}](videos/{video_id}.jsonl)"
                status = "✅"
            elif video.error:
                skill_link = "—"
                status = f"❌ {video.error[:20]}"
            else:
                skill_link = "—"
                status = "⏳ Pending"

            lines.append(f"| {yt_link} | {title} | {skill_link} | {status} |")

        # Add playlist sources if available
        playlists = {}
        for v in sorted_videos:
            if v.playlist_title and v.playlist_id:
                playlists[v.playlist_id] = v.playlist_title

        if playlists:
            lines.extend([
                "",
                "## Source Playlists",
                "",
            ])
            for pid, ptitle in playlists.items():
                lines.append(f"- [{ptitle}](https://youtube.com/playlist?list={pid})")

        self.index_file.write_text('\n'.join(lines))
        print(f"Index written to {self.index_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract attack skills from hacking tutorial videos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --playlists playlists.txt --output ./skills_corpus
  %(prog)s --video "https://youtube.com/watch?v=..." --output ./skills_corpus
  %(prog)s --playlists playlists.txt --output ./skills_corpus --rate-limit 5
        """
    )

    parser.add_argument(
        '--playlists', '-p',
        type=Path,
        help='File containing playlist URLs (one per line)'
    )
    parser.add_argument(
        '--video', '-v',
        type=str,
        help='Single video URL to process'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=Path('./skills_corpus'),
        help='Output directory (default: ./skills_corpus)'
    )
    parser.add_argument(
        '--rate-limit', '-r',
        type=float,
        default=2.0,
        help='Seconds between video extractions (default: 2.0)'
    )
    parser.add_argument(
        '--pattern',
        type=str,
        default='fp_extract_hack_skills',
        help='Fabric pattern to use (default: fp_extract_hack_skills)'
    )
    parser.add_argument(
        '--fabric-path',
        type=str,
        default=None,
        help='Path to fabric binary (default: auto-detect from PATH)'
    )

    args = parser.parse_args()

    if not args.playlists and not args.video:
        parser.error("Either --playlists or --video is required")

    extractor = SkillExtractor(
        output_dir=args.output,
        fabric_pattern=args.pattern,
        rate_limit=args.rate_limit,
        fabric_path=args.fabric_path
    )

    if args.playlists:
        extractor.process_playlists(args.playlists)
    elif args.video:
        extractor.process_single_video(args.video)


if __name__ == '__main__':
    main()
