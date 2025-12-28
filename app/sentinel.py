#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
#
# autumo Sentinel – Multi-Stage Supply-Chain Malware Scanner & Code Forensics
# Version 3.0.0 | Copyright (c) 2025 autumo GmbH
#
# IMPORTANT:
#   Scan time depends on workspace size, directory depth, and cache directories.
#   Not all matches are necessarily malicious; manual review required.
#
# DESCRIPTION:
#   Multi-stage malware scanning for filenames, scripts, and caches.
#   Supports plain and regex patterns, plus optional heuristic rules.
#
# CONFIGURATION:
#   - config/config.json
#   - rules/rules*.json
#
# OUTPUT:
#   - scan-hits-pivot.csv, scan-hits.csv (semicolon-separated)
#   - scan.log
#
# LICENSE:
#   SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-commercial
#   Dual license: GPL-3.0 (https://www.gnu.org/licenses/gpl-3.0.en.html)
#                 or commercial (contact autumo GmbH)
#
# ------------------------------------------------------------------------------


import os
import re
import sys
import json
import time
import platform
import argparse
import traceback
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

import emoji as em
from heuristics import HeuristicEngine, HeuristicRule
from build_info import COMMERCIAL_BUILD, VERSION

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------
CSV_BATCH_SIZE = 500
DEFAULT_LIMIT_LINE = 200
DEFAULT_LIMIT_LINE_RULE_HIT = 100
DEFAULT_LIMIT_PREVIEW_LINES_FILE = 10
DEFAULT_LIMIT_LINES_FILE_SCAN = 200
DEFAULT_LIMIT_CHARS_FILE_SCAN = 20000

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SCOPE_ORDER = {"line": 0, "file": 1}

# ------------------------------------------------------------
# Data Classes
# ------------------------------------------------------------
@dataclass
class CommentState:
    in_block: bool = False              # For C/JS/TS/Java block comments
    in_py_triple_double: bool = False   # Python """
    in_py_triple_single: bool = False   # Python '''

@dataclass
class RuleHitContext:
    rule: HeuristicRule  # rule itself
    matched_lines: list[tuple[str, int, str]] = field(default_factory=list)
    total_hits: int = 0

@dataclass
class FileHeuristicContext:
    file_path: Path
    # key: rule.id, value: RuleHitContext
    rules_hits: dict[str, RuleHitContext] = field(default_factory=dict)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def die(msg: str = "") -> None:
    if msg:
        print(f"\n{em.err()}ERROR: {msg}\n")
    sys.exit(1)

def info(msg: str) -> None:
    print(msg)

def show_root_or_mount_error(path: Path) -> None:
    print(f"\n{em.err()}ERROR: The directory '{path}' is too large or unsafe to scan.")
    print("\nThis tool is intended for scanning *project directories* and caches, not entire disks.")
    print("\nPlease provide the path to a development workspace or project root.")
    print("Examples:")
    print("   scanner ~/Development/my-project")
    print("   scanner ~/Development")
    print("\nTip: If you want to include local/global caches, use options: -l/-g\n")

def to_lower(s: str) -> str:
    return s.lower()

def safe_realpath(p: str | Path) -> Path:
    """
    Resolves a path to absolute canonical form.
    Always returns a Path object, even if resolution fails.
    Works on Windows, Linux, macOS.
    """
    try:
        return Path(p).resolve(strict=False)  # strict=False prevents FileNotFoundError
    except Exception:
        # Fallback: absolute Path without resolution
        try:
            return Path(p).absolute()
        except Exception:
            # Last resort: return Path from str
            return Path(str(p))

def get_os_type() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "macos"
    elif system == "Windows":
        return "windows"
    else:
        return "unknown"
    
def is_root_or_mount(path: Path, blocked_paths: list[str], blocked_windows_paths: list[str]) -> bool:
    path_str = str(path)
    system = platform.system()
    if system in ("Linux", "Darwin"):
        for bp in blocked_paths:
            if path_str == bp or path_str == bp + "/":
                show_root_or_mount_error(path)
                return True
    elif system == "Windows":
        for bp in blocked_windows_paths:
            if path_str.lower() == bp.lower() or path_str.lower() == bp.lower() + "\\":
                show_root_or_mount_error(path)
                return True
    return False

def load_patterns(file_path: Path) -> list[str]:
    patterns: list[str] = []
    if not file_path.is_file():
        return patterns
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            # Remove comments and spaces
            line = line.split("#", 1)[0].strip()
            if not line or all(c.isspace() for c in line):
                continue
            if line.startswith('"') and line.endswith('"'):
                line = line[1:-1]
                if not line:
                    continue
            patterns.append(line)
    return patterns

def print_progress(current: int, total: int, bar_length: int = 40) -> None:
    if total == 0:
        return
    try:
        fraction = current / total
        filled_length = int(bar_length * fraction)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        percent = int(fraction * 100)
        sys.stdout.write(f'\rProgress: |{bar}| {percent}% ({current}/{total})')
        sys.stdout.flush()
    except Exception:
        pass  # Ignore any errors in progress display

# ------------------------------------------------------------
# Usage
# ------------------------------------------------------------
def show_help() -> None:
    print(
        """
USAGE:
  sentinel <directory> [options]

OPTIONS:
  -l, --local
        Include local caches in the scan (OS-specific).
        Examples:
          - ~/.cache/node, ~/.npm (Linux / macOS)
          - %APPDATA%\\npm-cache, %LOCALAPPDATA%\\npm-cache (Windows)

  -g, --global
        Include global caches in the scan (OS-specific).
        Examples:
          - /tmp (Linux / macOS)
          - %LOCALAPPDATA%\\Temp (Windows)

  -k, --heuristics
        Enable heuristic scanning.
        Runs additional line- and file-based heuristic rules
        beyond static signature matching.

  --heuristics-level <low|medium|high>
        Limit heuristic rules to a minimum severity level:
          - low     all heuristic rules (default)
          - medium  medium and high severity only
          - high    high severity only

  --no-bail-out
        Prevents early termination when a finding is detected.
        The scanner continues analyzing the full file, but reports
        only the first match per rule.
        Use '--all-matches' to collect multiple findings per file.

  --all-matches
        Report all matches per rule and file instead of stopping after the
        first finding. May increase scan time and output size.
        Note: Rules marked as 'only_if_no_match' are ignored when this
        option is enabled.

  --forensic
        Enable forensic mode for exhaustive analysis and reporting.
        Equivalent to:
          '--no-bail-out' + '--all-matches'

  --exclude-dirs <dir1,dir2,...>
        Comma-separated list of directory names to exclude
        from scanning (matched by directory basename).
        Example:
          --exclude-dirs node_modules,.git,dist

  -c, --config <file>
        Path to the JSON configuration file.
        Default: config/config.json

  -h, --help
        Show this help message and exit.

DESCRIPTION:
  Performs a multi-stage malware scan focused on
  supply-chain threats and suspicious developer artifacts.

SCANNING INCLUDES:
  - Detection of suspicious filenames
  - Script-level indicators in shell scripts
  - Content pattern analysis in source files
  - Optional heuristic analysis (line- and file-based)
  - Optional scanning of local and global cache directories

CONFIGURATION:
  - config/config.json
  - patterns/files.txt
  - patterns/shell.txt
  - patterns/shell_rx.txt
  - patterns/content.txt
  - patterns/content_rx.txt
  - rules/rules*.json

EXAMPLES:
  sentinel myproject
  sentinel myproject -k
  sentinel myproject -k --heuristics-level medium
  sentinel myproject --forensic
  sentinel myproject -l --exclude-dirs node_modules,venv,dist,.git

"""
    )

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------
def print_header(
        version: str,
) -> None:
    license_text = (
        "Community / Open Version - GPLv3"
        if not COMMERCIAL_BUILD
        else (
            "Commercial / Full Version - \n"
            "          autumo Products General License v1.0"
        )
    )
    
    print()
    print("----------------------------------------------------------------")
    print()
    print(f"  {em.logo()}autumo Sentinel v{version} - Copyright 2025 autumo GmbH")
    print()
    print(f"  License: {license_text}")
    print()
    print("  Multi-stage supply-chain malware scanning with pattern-based")
    print("  detection and heuristic analysis.")
    print()
    print("  Scan duration depends on directory depth, workspace size,")
    print("  number of files, cache directory size if scanning caches.")
    print()
    print("  Important Notice:")
    print("    - No scanning method can guarantee 100% detection.")
    print("    - Not all matches are necessarily dangerous.")
    print("    - Manual review is always required.")
    print()
    print("----------------------------------------------------------------")
    print()

# ------------------------------------------------------------
# Scanner Class
# ------------------------------------------------------------
class DevScanner:
    def __init__(
        self,
        root_dir: Path,
        config_path: str,
        local_scan: bool = False,
        global_scan: bool = False,
        heuristics_enabled: bool = False,
        heuristics_level: str | None = "low",
        no_bail_out: bool = False,
        all_matches: bool = False,
        exclude_dirs: list[str] | None = None
    ):
        self.root_dir = safe_realpath(root_dir)
        self.local_scan = local_scan
        self.global_scan = global_scan
        self.all_matches = all_matches
        self.heuristics_enabled = heuristics_enabled
        self.heuristics_level = heuristics_level
        self.heuristics = None
        self.no_bail_out = no_bail_out
        self.exclude_dirs = exclude_dirs

        self.log = None

        # Total hits counter
        self.total_hits = 0

        # Pivot overview
        self.pivot = defaultdict(lambda: [None, 0]) 

        # Load config
        self.load_config(config_path)

        # Version check
        version=self.config["version"]
        check_version = f"{version}c" if COMMERCIAL_BUILD else version
        if check_version != VERSION:
            die("Version mismatch between configuration and build")

        # Header
        print_header(version)

        # Debug mode
        self.debug_mode = self.config.get("debug_mode", False)

        # Bail-out limits
        self.max_lines_file_scan = self.config["limits"].get("max_lines_file_scan", DEFAULT_LIMIT_LINES_FILE_SCAN)
        self.max_chars_file_scan = self.config["limits"].get("max_chars_file_scan", DEFAULT_LIMIT_CHARS_FILE_SCAN)

        # Load extensions for comment stripping
        self.block_comment_extensions = [
            ext for key in ["c_cpp", "javascript", "typescript", "java", "csharp", "php"] 
            for ext in self.config["artifacts"]["extensions"].get(key, [])
        ]

        # Setup logging
        self.log_file = Path(self.config["log_file"])
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.log = self.log_file.open("w", encoding="utf-8")

        # Heuristics
        if self.heuristics_enabled:
            if self.heuristics_level is None:
                self.heuristics_level = "low"
            try:
                self.load_rules_config(Path(self.config["rules_path"]))
                self.init_rules()
            except FileNotFoundError as e:
                if self.debug_mode:
                    self.log.write(f"Stacktrace: {traceback.format_exc()}\n")
                die(f"Heuristics config file not found: {e}")
            except ValueError as e:
                if self.debug_mode:
                    self.log.write(f"Stacktrace: {traceback.format_exc()}\n")
                die(f"Error loading heuristics config: {e}")
            except Exception as e:
                if self.debug_mode:
                    self.log.write(f"Stacktrace: {traceback.format_exc()}\n")
                die(f"Unexpected error: {e}")

        # Prepare batch hits
        self.batch_hits: list[tuple[Path, int, str, str]] = []

        # General setup
        self.csv_file = Path(self.config["csv_file"])
        self.csv_file.parent.mkdir(parents=True, exist_ok=True)
        self.csv_file_pivot = Path(self.config["csv_pivot_file"])
        self.csv_file_pivot.parent.mkdir(parents=True, exist_ok=True)

        self.max_line_length = self.config["limits"].get("max_line_length", DEFAULT_LIMIT_LINE)
        self.max_line_rule_hit_length = self.config["limits"].get("max_line_rule_hit_length", DEFAULT_LIMIT_LINE_RULE_HIT)
        self.max_preview_lines_file = self.config["limits"].get("max_preview_lines_file", DEFAULT_LIMIT_PREVIEW_LINES_FILE)

        # Patterns
        self.patterns_files = load_patterns(Path(self.config["patterns"]["files"]))

        self.patterns_shell = load_patterns(Path(self.config["patterns"]["shell"]))
        self.patterns_shell_rx = []
        for p in load_patterns(Path(self.config["patterns"]["shell_rx"])):
            try:
                self.patterns_shell_rx.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                die(f"Invalid regex pattern in shell_rx.txt: '{p}' -> {e}")

        self.patterns_content = load_patterns(Path(self.config["patterns"]["content"]))
        self.patterns_content_rx = []
        for p in load_patterns(Path(self.config["patterns"]["content_rx"])):
            try:
                self.patterns_content_rx.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                die(f"Invalid regex pattern in content_rx.txt: '{p}' -> {e}")

        self.patterns_shell_all = self.patterns_shell + self.patterns_shell_rx
        self.patterns_content_all = self.patterns_content + self.patterns_content_rx

        # Artifacts
        self.unix_shell_extensions = self.config["artifacts"]["extensions"]["unix_shell"] 
        self.win_shell_extensions = self.config["artifacts"]["extensions"]["windows_shell"]
        content_keys = [
            "javascript", "typescript", "python", "php", "ruby",
            "go", "java", "c_cpp", "rust", "lua", "perl", "swift", "config_misc"
        ]
        self.content_extensions = [
            ext
            for key in content_keys
            for ext in self.config["artifacts"]["extensions"].get(key, [])
        ]
        self.content_files = [f.lower() for f in self.config["artifacts"].get("content_files", [])]

        # Cache dirs
        self.os_type = get_os_type()
        self.cache_dirs_local: list[str] = self.config["cache_dirs"][self.os_type]["local"]
        self.cache_dirs_global: list[str] = self.config["cache_dirs"][self.os_type]["global"]

        # Safety
        self.safety_config = self.config["safety"]

        # Initialize CSV
        self.csv_file.write_text("file;hits;pattern_or_rule;type_or_severity;rule_id;rule_type;line_number;line\n", encoding="utf-8")

        # Setup
        self.print_setup()

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    @staticmethod
    def sanitize_csv_value(s: str, max_len: int, limit: bool = True, remove_line_feed: bool = True) -> str:
        """
        CSV-sanitizes a string:
        - Escapes double quotes only
        - Replaces newlines with spaces
        - Optionally truncates long lines
        """
        if isinstance(s, re.Pattern):
            s = s.pattern
        if s is None:
            return ""
        
        # Escape only double quotes
        s = s.replace('"', '""')
        
        if remove_line_feed:
            s = s.replace("\n", " ").replace("\r", " ")
        
        s = s.strip()
        if not s:
            return ""
        
        if limit and len(s) > max_len:
            s = s[:max_len] + " [truncated]"
        
        # Wrap in double quotes (so ; is safe inside)
        return f'"{s}"'
    
    @staticmethod
    def severity_to_rank(sev: str) -> int:
        return {"low": 1, "medium": 2, "high": 3}.get(sev.lower(), 1)

    def check_root_protection(self) -> None:
        if self.safety_config.get("root_protection", True):
            if is_root_or_mount(self.root_dir,
                                self.safety_config.get("blocked_paths", []),
                                self.safety_config.get("blocked_windows_paths", [])):
                die()

    def load_config(self, config_path: str) -> None:
        config_path = Path(config_path)
        if not config_path.is_file():
            die("Config file config/config.json not found")
        with config_path.open("r", encoding="utf-8") as f:
            self.config: dict = json.load(f)

    def rules_sort_key(self, rule: dict):
        severity = rule.get("severity", "low").lower()
        priority = rule.get("priority", 100)
        scope = rule.get("scope", "line").lower()
        only_if_no_match = rule.get("only_if_no_match", False)

        return (
            SEVERITY_ORDER.get(severity, 99),   # 1) Severity
            -priority,                          # 2) Priority (only inside severity)
            SCOPE_ORDER.get(scope, 99),         # 3) Scope (line before file)
            1 if only_if_no_match else 0        # 4) Overlap (only_if_no_match = False, technical)
        )

    def load_rules_config(self, config_path: Path) -> None:
        if not config_path.exists():
            die(f"Rules config path {config_path} not found")
        if config_path.is_dir():
            files = sorted(config_path.glob("rules*.json"))
        else:
            files = [config_path]

        # Load all rules*.json files and merge rules
        merged_rules = []
        rule_index = {}

        if self.heuristics_level == "high":
            allowed_severities = ["high"]
        elif self.heuristics_level == "medium":
            allowed_severities = ["medium", "high"]
        else:
            allowed_severities = ["low", "medium", "high"]

        low = 0
        medium = 0
        high = 0

        for path in files:
            try:
                with path.open("r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except json.JSONDecodeError as e:
                die(f"Invalid JSON in {path}: {e}")
            except OSError as e:
                die(f"Cannot read rules file {path}: {e}")

            rules = cfg.get("rules")
            if not isinstance(rules, list):
               die(f"'rules' must be a list in {path}")

            for idx, rule in enumerate(rules):
                rid = rule.get("id")
                if not rid:
                    die(f"Rule without id in {path} (index {idx})")

                if rid in rule_index:
                    die(
                        f"Duplicate rule id '{rid}' found in {path}.\n"
                        f"Originally defined in: {rule_index[rid]}\n"
                        f"Duplicate rule data:\n{json.dumps(rule, indent=2)}"
                    )

                severity = rule.get("severity", "unknown").lower()
                if severity not in ["low", "medium", "high"]:
                    die(f"Invalid severity {severity} found in rule {rid}")

                if severity not in allowed_severities:
                    continue

                if severity == "low":
                    low +=1
                elif severity == "medium":
                    medium +=1
                else:
                    high +=1

                rule_index[rid] = path
                rule["_source_file"] = str(path)
                merged_rules.append(rule)

        mr_len = len(merged_rules)
        if not merged_rules:
            die(f"No rules found in {config_path}")

        info(f"{em.disk()}Loaded rules with level ≥ '{self.heuristics_level.upper()}':")
        info(f"- Low:    {low}")
        info(f"- Medium: {medium}")
        info(f"- High:   {high}\n")

        c_len = low + medium + high
        if mr_len != c_len:
            die(f"Merged rules count mismatch: {mr_len} loaded, {c_len} expected from sum of severities")

        # Sort rules - high → medium → low and
        merged_rules.sort(key=self.rules_sort_key)

        # Final merged config
        self.heuristics_config = {
            "rules": merged_rules
        }

        if self.debug_mode:
            # Row width
            severity_width = max(len(r['severity']) for r in merged_rules) + 2
            priority_width = max(len(str(r.get('priority', 1))) for r in merged_rules) + 6  # "prio X"
            scope_width = max(len(r.get('scope', '')) for r in merged_rules) + 2
            overlap_width = max(len('NO-OVERLAP' if r.get('only_if_no_match') else 'OVERLAP') for r in merged_rules) + 2
            id_width = max(len(r['id']) for r in merged_rules) + 2

            info(f"{em.order()}Rules execution order:")
            for r in merged_rules:
                severity = r['severity'].upper()
                overlap = 'NO-OVERLAP' if r.get('only_if_no_match') else 'OVERLAP'
                priority = r.get('priority', 1)
                scope = r.get('scope', '')
                info(f"{severity:<{severity_width}} | "
                    f"prio {priority:<{priority_width}} | "
                    f"{scope:<{scope_width}} | "
                    f"{overlap:<{overlap_width}} | "
                    f"{r['id']:<{id_width}}")
            info("")

    def init_rules(self) -> None:
        rules = self.heuristics_config.get("rules", [])

        # Filters the rules based on the selected heuristics level.
        # Only rules with severity >= the chosen level are kept.
        # Example:
        #   - level="medium" -> keeps rules with "medium" and "high"
        #   - level="high"   -> keeps only rules with "high"
        if self.heuristics_level:
            max_rank = DevScanner.severity_to_rank(self.heuristics_level)
            rules = [r for r in rules if DevScanner.severity_to_rank(r.get("severity", "low")) >= max_rank]

        rules_config = {"rules": rules}
        self.heuristics = HeuristicEngine(self.config, rules_config, self.no_bail_out, self.log)

    def count_relevant_files(self, path: Path) -> int:
        """
        Count files relevant for scanning:
        - shell extensions
        - content extensions
        - content filenames
        """
        total = 0
        for dirpath, _, filenames in os.walk(path):
            # Exclude directories by basename
            if self.exclude_dirs and Path(dirpath).name in self.exclude_dirs:
                continue

            for fname in filenames:
                file_path = safe_realpath(Path(dirpath) / fname)
                if not isinstance(file_path, Path):
                    file_path = Path(file_path)

                ext = file_path.suffix.lower()
                if self.os_type == "windows":
                    if ext in self.win_shell_extensions or ext in self.content_extensions or fname.lower() in self.content_files:
                        total += 1
                else:
                    if ext in self.unix_shell_extensions or ext in self.content_extensions or fname.lower() in self.content_files:
                        total += 1
        return total

    def strip_comments(self, line: str, ext: str, state: CommentState, shell_exts: list) -> tuple[bool, str]:
        """
        Returns (skip_line, processed_line)

        Handles:
        - Shell comments (#)
        - Lines starting with '#' are skipped
        - Inline '#' is left mostly intact to avoid removing '#' inside strings
        - Python comments
        - Single-line '#' comments
        - Triple-quoted strings ('''...''' or \"\"\"...\"\"\"), including single-line triple-quote cases
        - Keeps code outside comments, skips lines inside multi-line triple-quoted strings
        - C / JS / TS / Java / C# comments
        - Block comments (/* ... */), multi-line or inline
        - Single-line comments (//)
        - Inline code before '//' is kept if non-empty

        Notes:
        - The function is heuristic: minor imperfections (e.g., '#' inside strings) may occur
        - Perfect parsing of every language is **not required** for the scanner
        - Despite small inaccuracies, hits in the overall code context will still be found reliably
        - External parsing libraries are unnecessary; this approach balances correctness and performance
        """

        stripped = line.lstrip()

        # -------- Shell comments --------
        if ext in shell_exts:
            if stripped.startswith("#"):
                return True, ""
            
            # Inline comments: # only remove if not in quotes
            single, double = False, False
            for i, c in enumerate(line):
                if c == "'" and not double:
                    single = not single
                elif c == '"' and not single:
                    double = not double
                elif c == "#" and not single and not double:
                    line = line[:i].rstrip()
                    break

        # -------- Python comments --------
        if ext == ".py":
            # Handle triple-quoted blocks
            if '"""' in line or "'''" in line:
                # Count before removing, for toggling state
                triple_double_count = line.count('"""')
                triple_single_count = line.count("'''")
                # Remove single-line triple-quoted strings
                line = re.sub(r'("""|\'\'\').*?(?:\1)', '', line)
                # Toggle state for each occurrence
                for _ in range(triple_double_count):
                    state.in_py_triple_double = not state.in_py_triple_double
                for _ in range(triple_single_count):
                    state.in_py_triple_single = not state.in_py_triple_single
            if state.in_py_triple_double or state.in_py_triple_single:
                return True, ""
            if stripped.startswith("#"):
                return True, ""
            # Inline python comment
            single, double = False, False
            for i, c in enumerate(line):
                if c == "'" and not double:
                    single = not single
                elif c == '"' and not single:
                    double = not double
                elif c == "#" and not single and not double:
                    line = line[:i].rstrip()
                    break

        # -------- C / JS / TS / Java / C# --------
        if ext in self.block_comment_extensions:
            # If already inside block comment
            if state.in_block:
                if "*/" in line:
                    state.in_block = False
                return True, ""
            # Remove inline block comments (code /* comment */ code)
            line = re.sub(r'/\*.*?\*/', '', line)
            # Start of multiline block comment
            if "/*" in line:
                state.in_block = True
                return True, ""
            # Inline // comments → keep code before
            if "//" in line:
                before, after = line.split("//", 1)
                if before.strip():
                    line = before
                else:
                    return True, ""

        # Final cleanup
        if not line.strip():
            return True, ""

        return False, line

    # ------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------
    def record_hit(
            self, file_path: Path, 
            hits_per_entry: int, 
            pattern_or_rule: str, 
            type_or_severity: str, 
            rule_id: str,
            rule_type: str,
            line_no: int, 
            line: str, 
            limit_line: bool = True, 
            remove_line_feed: bool = True
        ) -> None:
        if isinstance(pattern_or_rule, re.Pattern):
            pattern_or_rule = pattern_or_rule.pattern

        file_path = DevScanner.sanitize_csv_value(str(file_path), self.max_line_length, limit=False, remove_line_feed=True)
        pattern_or_rule = DevScanner.sanitize_csv_value(pattern_or_rule, self.max_line_length, limit=False, remove_line_feed=True)
        type_or_severity = DevScanner.sanitize_csv_value(type_or_severity, self.max_line_length, limit=False, remove_line_feed=True)
        rule_id = DevScanner.sanitize_csv_value(rule_id, self.max_line_length, limit=False, remove_line_feed=True) if rule_id else ""
        rule_type = DevScanner.sanitize_csv_value(rule_type, self.max_line_length, limit=False, remove_line_feed=True) if rule_type else ""
        line = DevScanner.sanitize_csv_value(line.strip(), self.max_line_length, limit=limit_line, remove_line_feed=remove_line_feed)

        # Add to batch
        self.batch_hits.append((file_path, hits_per_entry, pattern_or_rule, type_or_severity, rule_id, rule_type, line_no, line))
        self.total_hits += 1

        # Add to pivot: always increase +1
        self.pivot[pattern_or_rule][1] += 1
        if self.pivot[pattern_or_rule][0] is None:
            self.pivot[pattern_or_rule][0] = type_or_severity

        # Batch write every x hits
        if len(self.batch_hits) >= CSV_BATCH_SIZE:
            try:
                with self.csv_file.open("a", encoding="utf-8") as f:
                    for hit in self.batch_hits:
                        f.write(f"{hit[0]};{hit[1]};{hit[2]};{hit[3]};{hit[4]};{hit[5]};{hit[6]};{hit[7]}\n")
                self.batch_hits.clear()  # Delete batch
            except Exception as e:
                if self.log:
                    self.log.write(f"ERROR writing to CSV: {e}\n")

    # ------------------------------------------------------------
    # Scan Methods
    # ------------------------------------------------------------
    def scan_filenames(self) -> int:
        """
        A hygiene and awareness check for developers within project directories
        """
        hits = 0
        for dirpath, _, filenames in os.walk(self.root_dir):
            for fname in filenames:

                if fname in self.patterns_files:
                    file_path = safe_realpath(Path(dirpath) / fname)
                    if not isinstance(file_path, Path):
                        file_path = Path(file_path)

                    self.record_hit(file_path, 1, "[filename-only]", "filename", "", "", 0, "", limit_line=False)
                    hits += 1
        return hits

    def scan_directory(self, path: Path) -> tuple[int, int]:
        hits = 0
        path = safe_realpath(path)
        if not path.exists():
            return hits, 0

        # Count relevant files for processing directory for progress tracking
        total_files_in_dir = self.count_relevant_files(path)
        processed_files = 0

        fhc: FileHeuristicContext | None = None

        for dirpath, _, filenames in os.walk(path):
            # Exclude directories by basename
            if Path(dirpath).name in self.exclude_dirs:
                continue

            for fname in filenames:
                file_path = safe_realpath(Path(dirpath) / fname)
                if not isinstance(file_path, Path):
                    file_path = Path(file_path)

                # Bail-out vaiables
                sum_chars = 0
                sum_lines = 0

                # Note: file_path.suffix -> ".gz", file_path.suffixes -> [".tar", ".gz"]
                ext = file_path.suffix.lower()

                # Decide whether to perform a content or shell scan
                content_files_scan = fname.lower() in self.content_files
                content_scan = ext in self.content_extensions or content_files_scan
                if self.os_type == "windows":
                    shell_scan = ext in self.win_shell_extensions
                else:
                    shell_scan = ext in self.unix_shell_extensions

                # If none of the above applies, skip
                if not content_scan and not shell_scan:
                    continue

                try:
                    state = CommentState()
                    try:
                        # First try UTF-8
                        with file_path.open("r", encoding="utf-8") as f:
                            lines = f.readlines()
                    except UnicodeDecodeError:
                        # Fallback to Latin-1
                        with file_path.open("r", encoding="latin-1", errors="replace") as f:
                            lines = f.readlines()

                    if self.heuristics_enabled:
                        fhc = FileHeuristicContext(file_path=file_path)

                    # Did a rule fire witjhin the line-scope?
                    line_rule_matched_in_file = False

                    # Rules for line-based scope
                    line_rules_base = [r for r in self.heuristics.rules if r.scope == "line" and self.heuristics_enabled and self.heuristics.rules]

                    # For heuristics line storage and file-based heuristics rules
                    file_lines = []

                    # Line loop
                    for lineno, line in enumerate(lines, start=1):
                        original_line = line.rstrip("\n\r")

                        # Strip comments if shell file
                        if shell_scan or content_scan:
                            if self.os_type == "windows":
                                skip, line_proc = self.strip_comments(original_line, ext, state, self.win_shell_extensions)
                            else:
                                skip, line_proc = self.strip_comments(original_line, ext, state, self.unix_shell_extensions)

                            if skip:
                                continue
                        else:
                            line_proc = original_line.strip()

                        # Store line for file-based heuristics
                        if self.heuristics_enabled:
                           file_lines.append(original_line)

                        # Prepare line for lowercase matching
                        line_lc = to_lower(line_proc)

                        # Check normal patterns
                        matched = False

                        # Content scan nur auf content_patterns_all
                        if content_scan:
                            patterns_to_check = self.patterns_content_all
                        # Shell scan nur auf shell_patterns_all
                        elif shell_scan:
                            patterns_to_check = self.patterns_shell_all
                        else:
                            patterns_to_check = []

                        pattern_normal_match = False
                        for pattern in patterns_to_check:
                            if isinstance(pattern, str):
                                if pattern.lower() in line_lc:
                                    matched = True
                                    pattern_normal_match = True
                                    break
                            else:
                                if re.search(pattern, line_proc):
                                    matched = True
                                    break

                        # Record hit
                        if matched:
                            if (pattern_normal_match):
                                self.record_hit(file_path, 1, pattern, "normal", "", "", lineno, original_line.strip(), limit_line=True)
                            else:
                                self.record_hit(file_path, 1, pattern, "regex", "", "", lineno, original_line.strip(), limit_line=True)
                            hits += 1

                        # Line-based heuristics
                        if self.heuristics_enabled and self.heuristics:
                            for rule in line_rules_base:
                                if not self.all_matches and rule.only_if_no_match and line_rule_matched_in_file:
                                    continue

                                matched, severity = rule.matches(line_proc, ext)
                                if matched:
                                    line_rule_matched_in_file = True
                                    if rule.id not in fhc.rules_hits:
                                        fhc.rules_hits[rule.id] = RuleHitContext(rule=rule)
                                    rhc = fhc.rules_hits[rule.id]
                                    rhc.matched_lines.append((severity, lineno, original_line))
                                    rhc.total_hits += 1

                        # Bail-out ?
                        if not self.no_bail_out:
                            sum_lines += 1
                            sum_chars += len(original_line)
                            if (sum_lines >= self.max_lines_file_scan):
                                break
                            if (sum_chars >= self.max_chars_file_scan):
                                break

                        # End of line loop!

                    # Check whether line-based heuristic threshold has been reached for all rules
                    if self.heuristics_enabled and self.heuristics:
                        for rhc in fhc.rules_hits.values():
                            if rhc.total_hits >= rhc.rule.heuristic_threshold:
                                rule_name = f"[heuristic threshold reached]: {rhc.rule.name}"
                                severity = rhc.matched_lines[0][0] if rhc.matched_lines else ""
                                first_lineno = rhc.matched_lines[0][1] if rhc.matched_lines else 0
                                combined_lines = ""
                                if rhc.matched_lines:
                                    ml_len = len(rhc.matched_lines)
                                    lines_out = []
                                    # Collect all lines, with line numbers and colons
                                    for _, lineno, line in rhc.matched_lines:
                                        line = line.replace("\n", " ").replace("\r", " ").strip()
                                        if len(line) > self.max_line_rule_hit_length:
                                            line = line[:self.max_line_rule_hit_length] + " [truncated]"
                                        if ml_len > 1:
                                            lines_out.append(f"{lineno}: {line}")
                                        else:
                                            lines_out.append(line)

                                    combined_lines = "\n".join(lines_out)

                                hits += 1
                                self.record_hit(file_path, rhc.total_hits, rule_name, severity, rhc.rule.id, rhc.rule.type, first_lineno, combined_lines, limit_line=False, remove_line_feed=False)

                    # File-based heuristics
                    if self.heuristics_enabled and self.heuristics:
                        file_rule_matched = False
                        # Rule filters basend on conditions
                        file_rules_to_check = [
                            r for r in self.heuristics.rules
                            if r.scope == "file"
                            and (self.all_matches or not (r.only_if_no_match and file_rule_matched))
                        ]
                        for rule in file_rules_to_check:
                            matched, severity = rule.matches(file_lines, ext=ext)
                            if matched:
                                file_rule_matched = True
                                file_rule_name = "[heuristic file match]: " + rule.name
                                matched_lines = rule.get_matched_lines()
                                combined_lines = ""
                                line_hits = len(matched_lines) if matched_lines else 1

                                if matched_lines:
                                    # --- Build preview lines with truncation ---
                                    lines_to_preview = []
                                    for line in matched_lines:
                                        if len(lines_to_preview) >= self.max_preview_lines_file:
                                            break
                                        line_preview = line.replace("\n", " ").replace("\r", " ").strip()
                                        if len(line_preview) > self.max_line_rule_hit_length:
                                            line_preview = line_preview[:self.max_line_rule_hit_length] + " [truncated]"
                                        lines_to_preview.append(line_preview)

                                    combined_lines = "\n".join(lines_to_preview)

                                    # --- Special handling for JS/TS minified files ---
                                    if rule.minified:
                                        combined_lines = "[File content omitted – likely contains bundled or minified code]"
                                    # --- Regular previews ---
                                    elif len(matched_lines) > self.max_preview_lines_file:
                                        combined_lines = f"Preview of matched lines (max. {self.max_preview_lines_file}):\n" + combined_lines
                                    elif len(matched_lines) > 1:
                                        combined_lines = "Matched lines:\n" + combined_lines
                                    # 1 line = pass

                                else:
                                    combined_lines = "[File content omitted]"

                                self.record_hit(file_path, line_hits, file_rule_name, severity, rule.id, rule.type, 0, combined_lines, limit_line=False, remove_line_feed=False)
                                hits += 1

                except Exception as e:
                    if self.log:
                        self.log.write(f"ERROR scanning file {file_path}: {e}\n")
                        if self.debug_mode:
                            self.log.write(f"Stacktrace: {traceback.format_exc()}\n")

                processed_files += 1
                print_progress(processed_files, total_files_in_dir)

        # Write remaining hits
        if self.batch_hits:
            try:
                with self.csv_file.open("a", encoding="utf-8") as f:
                    for hit in self.batch_hits:
                        f.write(f"{hit[0]};{hit[1]};{hit[2]};{hit[3]};{hit[4]};{hit[5]};{hit[6]};{hit[7]}\n")
                self.batch_hits.clear()  # Delete batch
            except Exception as e:
                if self.log:
                    self.log.write(f"ERROR writing to CSV: {e}\n")

        if total_files_in_dir > 0:
            print_progress(total_files_in_dir, total_files_in_dir)

        info("")
        info(f"{em.info()}Scanned: {processed_files} relevant files in {path}")
        return hits, processed_files

    def scan_caches(self, local: bool = True) -> tuple[int, int]:
        hits = 0
        dirs = self.cache_dirs_local if local else self.cache_dirs_global
        total_files_in_cache = 0
        for d in dirs:
            expanded = Path(os.path.expandvars(os.path.expanduser(d)))
            if expanded.exists():
                info(f"Scanning cache: {expanded}")
                h, tf = self.scan_directory(expanded)
                hits += h
                total_files_in_cache += tf
        return hits, total_files_in_cache

    # ------------------------------------------------------------
    # Print-Out/Log Functions
    # ------------------------------------------------------------
    def print_setup(self) -> None:
        print(f"{em.scan()}Scanning:")
        self.log.write(f"Scanning:\n")

        print(f"- Project directory:")
        print(f"  {self.root_dir}")
        self.log.write(f"- Project directory:\n")
        self.log.write(f"  {self.root_dir}\n")

        if self.local_scan:
            print("- Including local caches")
            self.log.write("- Including local caches\n")
        if self.global_scan:
            print("- Including global caches")
            self.log.write("- Including global caches\n")

        if self.heuristics_enabled:
            level = (self.heuristics_level or "low").lower()

            print(f"- Heuristic scanning enabled (level ≥ {level})")
            self.log.write(f"- Heuristic scanning enabled (level ≥ {level})\n")

            if level == "high":
                severities = "HIGH"
            elif level == "medium":
                severities = "MEDIUM, HIGH"
            else:
                severities = "LOW, MEDIUM, HIGH"

            print(f"- Rule severities: {severities}")
            self.log.write(f"- Rule severities: {severities}\n")

        if self.no_bail_out and self.all_matches:
            print("- Forensic mode activated")
            self.log.write(f"- Forensic mode activated\n")
        else:
            if self.no_bail_out:
                print("- Bail-out disabled (no line/file limits)")
                self.log.write(f"- Bail-out disabled (no line/file limits)\n")
            if self.all_matches:
                print("- All-matches mode enabled (ignore only_if_no_match)")
                self.log.write(f"- All-matches mode enabled (ignore only_if_no_match)\n")

        if self.exclude_dirs:
            print(f"- Excluded directories: {', '.join(self.exclude_dirs)}")
            self.log.write(f"- Excluded directories: {', '.join(self.exclude_dirs)}\n")

        info("\n----------------------------------------------------------------")
        self.log.write("----------------------------------------------------------------\n")
        self.log.flush()
        print()

    def print_scan_summary(self, duration: float):
        minutes, seconds = divmod(duration, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            print(f"- Scan completed in {int(hours)}h {int(minutes)}m {seconds:.2f}s")
            self.log.write(f"- Scan completed in {int(hours)}h {int(minutes)}m {seconds:.2f}s\n")
        elif minutes:
            print(f"- Scan completed in {int(minutes)}m {seconds:.2f}s")
            self.log.write(f"- Scan completed in {int(minutes)}m {seconds:.2f}s\n")
        else:
            print(f"- Scan completed in {seconds:.2f}s")
            self.log.write(f"- Scan completed in {seconds:.2f}s\n")

    # ------------------------------------------------------------
    # Run
    # ------------------------------------------------------------
    def run(self) -> None:
        # Safety
        self.check_root_protection()

        # Scanned files counter
        total_files_scanned = 0

        # Section hits counter
        section_hits = 0

        # Start time
        scan_start = time.perf_counter()

        # 1) Filenames scan
        info(f"\n{em.scan()}Scanning for suspicious filenames...")
        section_hits = self.scan_filenames()
        if section_hits > 0:
            info(f"{em.warn()}Found {section_hits} suspicious filenames in project directory\n")
            self.log.write(f"Found {section_hits} suspicious filenames in project directory\n")
        else:
            info(f"{em.ok()}No suspicious filenames found\n")
            self.log.write("No suspicious filenames found\n")
        self.log.flush()

        # 2) Scan root directory
        info(f"\n{em.scan()}Scanning for suspicious contents...")
        section_hits, fc = self.scan_directory(self.root_dir)
        total_files_scanned += fc
        if section_hits > 0:
            info(f"{em.warn()}Found {section_hits} suspicious patterns/rules in project directory\n")
            self.log.write(f"Found {section_hits} suspicious patterns/rules in project directory\n")
        else:
            info(f"{em.ok()}No suspicious patterns/rules found in project directory\n")
            self.log.write("No suspicious patterns/rules found in project directory\n")
        self.log.flush()
        
        # 3) Scan local caches
        if self.local_scan:
            info(f"\n{em.scan()}Scanning local caches...")
            section_hits, fc = self.scan_caches(local=True)
            total_files_scanned += fc
            if section_hits > 0:
                info(f"{em.warn()}Found {section_hits} suspicious patterns/rules in local caches\n")
                self.log.write(f"Found {section_hits} suspicious patterns/rules in local caches\n")
            else:
                info(f"{em.ok()}No suspicious patterns/rules found in local caches\n")
                self.log.write("No suspicious patterns/rules found in local caches\n")
        self.log.flush()

        # 4) Scan global caches if -g
        if self.global_scan:
            info(f"\n{em.glob()}Scanning global caches...")
            section_hits, fc = self.scan_caches(local=False)
            total_files_scanned += fc
            if section_hits > 0:
                info(f"{em.warn()}Found {section_hits} suspicious patterns/rules in global caches\n")
                self.log.write(f"Found {section_hits} suspicious patterns/rules in global caches\n")
            else:
                info(f"{em.ok()}No suspicious patterns/rules found in global caches\n")
                self.log.write("No suspicious patterns/rules found in global caches\n")
        self.log.flush()
        
        # Summary
        info("\n----------------------------------------------------------------")
        info("")
        self.log.write("----------------------------------------------------------------\n")
        info(f"{em.info()}{total_files_scanned} files scanned")
        self.log.write(f"{total_files_scanned} files scanned\n") 
        if self.total_hits == 0:
            info(f"{em.ok()}No suspicious patterns/rules found")
            self.log.write("No suspicious patterns/rules found\n") 
        else:
            info(f"{em.warn()}Suspicious patterns/rules found:")
            self.log.write(f"Suspicious patterns/rules found:\n")
            info(f"- Total hits: {self.total_hits}")
            self.log.write(f"- Total hits: {self.total_hits}\n")
            info(f"- CSV report: {self.csv_file}")
            self.log.write(f"- CSV report: {self.csv_file}\n")
            # Write pivot
            try:
                self.csv_file_pivot.write_text("pattern_or_rule;type_or_severity;hits\n", encoding="utf-8")
                with self.csv_file_pivot.open("a", encoding="utf-8") as f:
                    for pattern_or_rule, (type_or_severity, hits) in sorted(self.pivot.items(), key=lambda x: x[1][1], reverse=True):
                        f.write(f"{pattern_or_rule};{type_or_severity};{hits}\n")
                info(f"- CSV pivot report: {self.csv_file_pivot}")
                self.log.write(f"- CSV pivot report: {self.csv_file_pivot}\n")
            except Exception as e:
                if self.log:
                    self.log.write(f"ERROR writing to pivot CSV: {e}\n")

        # End time
        scan_end = time.perf_counter()
        duration = scan_end - scan_start
        self.print_scan_summary(duration)

        info("")
        info("----------------------------------------------------------------\n")
        self.log.write("----------------------------------------------------------------\n")

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    # Check python version
    if sys.version_info < (3, 10):
        die("Python 3.10 or higher is required")

    # Create console arguments
    parser = argparse.ArgumentParser(
        description="autumo Sentinel – Multi-stage Supply-Chain Malware Scanner.",
        add_help=False
    )

    # Standard arguments
    parser.add_argument("directory", nargs="?", default=None, help="Project directory to scan")
    parser.add_argument("-l", "--local", dest="local_scan", action="store_true", help="Include local caches")
    parser.add_argument("-g", "--global", dest="global_scan", action="store_true", help="Include global caches")
    parser.add_argument("-c", "--config", default="config/config.json", help="Config JSON file")
    parser.add_argument("-k", "--heuristics", action="store_true", help="Enable heuristic scanning")
    parser.add_argument("--heuristics-level",choices=("low", "medium", "high"), help="Limit heuristics to a severity level (default: all)")
    parser.add_argument("--no-bail-out", action="store_true", help="Do not skip after a number of lines or characters (disable bail-out)")
    parser.add_argument("--all-matches", action="store_true", help="Do not skip rules marked as 'only_if_no_match'; evaluate all")
    parser.add_argument("--forensic", action="store_true", help="Enable forensic mode (equivalent to --no-bail-out and --all-matches)")
    parser.add_argument("--exclude-dirs", type=lambda s: [d.strip() for d in s.split(",") if d.strip()], help="Comma-separated list of directories to exclude from scanning")

    # Help
    parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")

    # Parse console arguments
    args = parser.parse_args()

    # Specific Help
    if args.help:
        show_help()
        sys.exit(0)

    # Check whether directory has been set
    if args.directory is None:
        print()
        print("Error: directory argument is required\n")
        parser.print_usage()  # Show usage only, not full help text
        print()
        print("Note: Use -h or --help for details.\n")
        print()
        sys.exit(1)

    # Apply forensic mode flags
    no_bail_out = args.no_bail_out or args.forensic
    all_matches = args.all_matches or args.forensic

    # Project directory
    root = Path(args.directory)

    # Initialize scanner
    scanner = DevScanner(
        root,
        config_path=args.config,
        local_scan=args.local_scan,
        global_scan=args.global_scan,
        heuristics_enabled=args.heuristics,
        heuristics_level=args.heuristics_level,
        no_bail_out=no_bail_out,
        all_matches=all_matches,
        exclude_dirs=args.exclude_dirs or []
    )

    # Run scan
    scanner.run()

if __name__ == "__main__":
    main()
