#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
#
# autumo Sentinel – Multi-Stage Supply-Chain Malware Scanner & Code Forensics
# Version 3.0.0 | Copyright (c) 2025 autumo GmbH
#
# DESCRIPTION:
#   Additional heuristic scanning engine for autumo Sentinel. 
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


from __future__ import annotations

import re
import sys
import math
import traceback
import collections
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union, Tuple, Dict, List, Any

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------
DEBUG_RULES_OUTPUT = False

DEFAULT_LIMIT_LINE_RULE_HIT = 100
DEFAULT_LIMIT_LINES_FILE_SCAN = 200
DEFAULT_LIMIT_CHARS_FILE_SCAN = 20000
DEFAULT_LIMIT_MINIFIED_LINE_AVG_LENGTH = 200

# ------------------------------------------------------------
# Data Classes
# ------------------------------------------------------------
@dataclass
class BailoutException(Exception):
    """Internal exception to abort line/file processing when limits are reached."""
    pass
@dataclass
class HeuristicRule:
    id: str
    name: str
    type: str
    scope: str            # "line" | "file"
    severity: str
    only_if_no_match: bool
    applies_to: Dict[str, Any]
    parameters: Dict[str, Any]
    heuristic_threshold: int = 1
    description: str = ""
    false_positive_note: str = ""
    priority: int = 100
    source_file: Path | None = None
    engine: HeuristicEngine | None = None

    # Reset states; a rule is stateful!
    sum_lines: int = 0
    sum_chars: int = 0
    matched_lines: List[str] = field(default_factory=list)
    bailout: bool = False
    minified: bool = False
    
    def matches(self, data: Union[str, List[str]], ext: str) -> Tuple[bool, str]:
        # Reset matched lines
        self.matched_lines = []
        self.sum_lines = 0
        self.sum_chars = 0
        self.bailout = False
        self.minified = False

        if self.scope == "line":
            return self.engine.check_line(self, line=data, ext=ext)
        elif self.scope == "file":
            return self.engine.check_file(self, lines=data, ext=ext)
        
        self.die(f"Scope {self.scope} is invalid, check rule id {self.id}")

    def get_matched_lines(self) -> List[str]:
        return self.matched_lines or []
    
    def has_bailout(self) -> bool:
        return self.bailout

    def is_minified(self) -> bool:
        return self.minified

# ------------------------------------------------------------
# Heuristic Engine
# ------------------------------------------------------------
class HeuristicEngine:
    """
    Executes heuristic checks based on JSON rules.
    Initialized only when -k / heuristics option is enabled.
    Heuristic Rules are stateful; reset states after using an instance!
    """

    def __init__(self, base_config: Dict[str, Any], config: Dict[str, Any], no_bail_out: bool, log=None) -> None:
        self.debug_mode = base_config.get("debug_mode", False)
        self.max_line_rule_hit_length = base_config["limits"].get("max_line_rule_hit_length", DEFAULT_LIMIT_LINE_RULE_HIT)
        self.max_lines_file_scan = base_config["limits"].get("max_lines_file_scan", DEFAULT_LIMIT_LINES_FILE_SCAN)
        self.max_chars_file_scan = base_config["limits"].get("max_chars_file_scan", DEFAULT_LIMIT_CHARS_FILE_SCAN)
        self.max_minified_line_avg_length = base_config["limits"].get("max_minified_line_avg_length", DEFAULT_LIMIT_MINIFIED_LINE_AVG_LENGTH)
        self.extensions = base_config["artifacts"]["extensions"]

        minified_ext_group_keys = ["javascript", "typescript"]
        self.js_ts_extensions = [
            ext
            for key in minified_ext_group_keys
            for ext in self.extensions.get(key, [])
        ]

        self.rules: List[HeuristicRule] = []
        self.no_bail_out = no_bail_out
        self.log = log

        # Load rules
        self._load_rules(config)

        # Dispatch table
        self._executors = {
            "string_length": self._check_string_length,              # line
            "base64_suspect": self._check_base64,                    # line
            "hex_suspect": self._check_hex,                          # line
            "path_access": self._check_paths,                        # line
            "keyword_combination": self._check_keyword_combo,        # line|file
            "obfuscation_strings": self._check_obfuscation_strings,  # line|file
            "obfuscation_vars": self._check_obfuscation_vars         # file
        }

    # Line-based
    def check_line(
        self,
        rule: HeuristicRule,
        *,
        line: str,
        ext: str,
        had_signature_match: bool = False
    ) -> Tuple[bool, str]:
        
        if rule.scope != "line":
            return False, None
        
        if had_signature_match:
            return False, None
        
        if not self._extension_applies(rule, ext):
            return False, None
        
        executor = self._executors.get(rule.type)
        if not executor:
            if self.log:
                self.log.write(f"Error: Unknown executor type '{rule.type}' in rule '{rule.id}'\n")
            self.die(f"Unknown executor type '{rule.type}' in rule '{rule.id}'\n")
            return False, None
        
        return executor(rule, line=line, ext=ext, scope="line"), rule.severity.lower()

    # File-based
    def check_file(
        self,
        rule: HeuristicRule,
        *,
        lines: List[str],
        ext: str,
        scan_context: str = None,
        had_signature_match: bool = False
    ) -> Tuple[bool, str]:

        if rule.scope != "file":
            return False, None

        if had_signature_match:
            return False, None

        if not self._scan_context_applies(rule, scan_context):
            return False, None

        if not self._extension_applies(rule, ext):
            return False, None

        executor = self._executors.get(rule.type)
        if not executor:
            if self.log:
                self.log.write(f"Error: Unknown executor type '{rule.type}' in rule '{rule.id}'\n")
            self.die(f"Unknown executor type '{rule.type}' in rule '{rule.id}'\n")
            return False, None

        sev = rule.severity.lower()

        # Merge lines into a single string for file-based checks
        if isinstance(lines, list):
            if rule.type == "keyword_combination":
                # Check for minified
                if ext in self.js_ts_extensions and 1 <= len(lines) <= 2:
                    avg_len = sum(len(l) for l in lines) / len(lines)
                    if avg_len > self.max_minified_line_avg_length:
                        rule.minified = True
                # Iterate lines
                for l in lines:
                    try:
                        # Still mark it as 'file', even we process line per line
                        executor(rule, line=l, ext=ext, scope="file")
                    except BailoutException:
                        return True, sev
                if len(rule.matched_lines) > 0:
                    return True, sev
                else:
                    return False, sev
                
            else:
                big_line = "\n".join(lines)
                return executor(rule, line=big_line, ext=ext, scope="file"), sev
        else:
            big_line = lines
            return executor(rule, line=big_line, ext=ext, scope="file"), sev

    # ------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------
    def _load_rules(self, config: Dict[str, Any]) -> None:

        # All sorting have already been placed here!
        rules_raw = config.get("rules", [])

        if DEBUG_RULES_OUTPUT and self.debug_mode:
            self.info("📜 Heuristic Engine - Rules loaded:")

        for raw in rules_raw:
            self._load_single_rule(raw)

        if DEBUG_RULES_OUTPUT and self.debug_mode:
            self.info("")

    def _load_single_rule(self, raw) -> None:
        try:
            id=raw["id"]
            if any(r.id == id for r in self.rules):
                self.die(f"Duplicate rule id detected: {id}")

            severity=raw.get("severity", "low")
            if severity not in ("low", "medium", "high"):
                self.die(
                    f"Invalid rule severity '{severity}' in rule id: {id}. "
                    "Allowed values are: low, medium, high."
                )

            source_file = Path(raw.get("_source_file")) if "_source_file" in raw else None

            rule = HeuristicRule(
                id=id,
                name=raw.get("name", raw["id"]),
                description=raw.get("description", ""),
                false_positive_note=raw.get("false_positive_note", ""),
                type=raw["type"],
                scope=raw["scope"],
                severity=severity,
                only_if_no_match=raw.get("only_if_no_match", False),
                applies_to=raw.get("applies_to", {}),
                parameters=raw.get("parameters", {}),
                heuristic_threshold=raw.get("heuristic_threshold", 1),
                priority=raw.get("priority", 100),
                source_file=source_file
            )
            rule.engine = self
            self.rules.append(rule)

            if DEBUG_RULES_OUTPUT and self.debug_mode:
                severity = rule.severity.upper()
                overlap_text = 'NO-OVERLAP' if rule.only_if_no_match else 'OVERLAP'
                self.info(f"{severity:<8} | prio {rule.priority:<7} | {rule.scope:<6} | {overlap_text:<12} | {rule.id}")
              
        except KeyError as e:
            if self.log:
                self.log.write(f"Missing required field {e} in rule: {raw}\n")
            self.die(f"Missing required field {e} in rule: {raw}")

        except Exception as e:
            if self.log:
                self.log.write(f"Error: Failed to load rule {raw.get('id', 'unknown')}: {e}\n")
            self.die(f"Error: Failed to load rule {raw.get('id', 'unknown')}: {e}")

    # ------------------------------------------------------------
    # Applicability helpers
    # ------------------------------------------------------------
    def _extension_applies(self, rule: HeuristicRule, ext: str) -> bool:
        exts = rule.applies_to.get("extensions")
        if not exts:
            return True  # No restriction
        
        resolved_exts = []
        for e in exts:
            if e in self.extensions:
                # e is a group -> dissolve
                resolved_exts.extend(self.extensions[e])
            elif e.startswith("."):
                # valid single extension
                resolved_exts.append(e)
            else:
                # unknown prefix or misconfiguration → log
                if self.log:
                    self.log.write(f"Error: Rule '{rule.id}': unknown extension/group '{e}'")
                self.die(f"Rule '{rule.id}': unknown extension/group '{e}'")
        
        return ext in resolved_exts

    def _scan_context_applies(self, rule: HeuristicRule, scan_context: str) -> bool:
        if scan_context is None:
            return True
        contexts = rule.applies_to.get("scan_context")
        if not contexts:
            return True
        """
        Example:
        "applies_to": {
            "extensions": ["unix_shell", ".js", ".py"],
            "scan_context": ["frontend", "backend"]
        }
        """
        return scan_context in contexts

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    def die(self, msg: str = "") -> None:
        if msg:
            print(f"\n❌ ERROR: {msg}\n")
        if self.debug_mode and self.log:
            self.log.write(f"Stacktrace: {traceback.format_exc()}\n")
        sys.exit(1)

    def info(self, msg: str) -> None:
        print(msg)

    @staticmethod
    def entropy(s: str) -> float:
        """Calculate the Shannon entropy of a character string"""
        if not s:
            return 0.0
        counts = collections.Counter(s)
        probs = [c / len(s) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    # ------------------------------------------------------------
    # Rule executors
    # ------------------------------------------------------------
    def _check_string_length(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        if (scope != "line"):
            if self.log:
                self.log.write(f"Error: Rule '{rule.id}': string_length executor only works in 'line' scope\n")
            self.die(f"Rule '{rule.id}': string_length executor only works in 'line' scope")

        min_len = rule.parameters.get("min_length", 0)
        return len(line) >= min_len

    def _check_base64(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        if (scope != "line"):
            if self.log:
                self.log.write(f"Error: Rule '{rule.id}': base64_suspect executor only works in 'line' scope\n")
            self.die(f"Rule '{rule.id}': base64_suspect executor only works in 'line' scope")
        
        min_len = rule.parameters.get("min_length", 0)
        if len(line) < min_len:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", line))

    def _check_hex(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        if (scope != "line"):
            if self.log:
                self.log.write(f"Error: Rule '{rule.id}': hex_suspect executor only works in 'line' scope\n")
            self.die(f"Rule '{rule.id}': hex_suspect executor only works in 'line' scope")

        min_len = rule.parameters.get("min_length", 0)
        if len(line) < min_len:
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]+", line))

    def _check_paths(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        if (scope != "line"):
            if self.log:
                self.log.write(f"Error: Rule '{rule.id}': path_access executor only works in 'line' scope\n")
            self.die(f"Rule '{rule.id}': path_access executor only works in 'line' scope")

        paths = rule.parameters.get("paths", [])
        return any(p in line for p in paths)

    #
    # Example:
    # ----------
    # Rule keywords: [["eval", "exec"], ["base64"], [{"regex": "obf_[a-z]+"}]]
    # Line: "eval(base64_decode(obf_xyz('data')))"
    # Matching process:
    #   - Group 1: "eval" matches → ✅
    #   - Group 2: "base64" matches → ✅
    #   - Group 3: regex "obf_[a-z]+" matches "obf_xyz" → ✅
    # Result: True (all groups have at least one match)
    #
    def _check_keyword_combo(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        """
        Evaluates whether a line satisfies a "keyword combination" heuristic rule.

        This executor supports flexible keyword rules for detecting suspicious or interesting
        patterns in code. It can handle single or multiple keyword groups, with optional
        thresholds per group. Each group represents a set of keywords where a minimum number
        must match in the line.

        Key concepts:
        -------------
        - Single-group rules:
            * At least **1 keyword** must be present by default if the group contains only a single keyword or regex.
            * If the group contains multiple keywords, at least **2 keywords** must match by default.
            * Threshold can be configured via the 'threshold' parameter, but will be automatically corrected if below the minimum (1 or 2 depending on group size).

        - Multi-group rules:
            * Each group is treated as a semantic AND (1 keyword per group must appear).
            * Thresholds for multi-group rules are ignored; internally forced to 1 per group.
            * This ensures that all groups contribute to the match requirement.

        - Keyword types:
            * String keywords: compared case-insensitively.
            * List of strings: all treated case-insensitively.
            * Dictionary with 'regex': compiled into a Python regex with optional flags ('IGNORECASE', 'MULTILINE').
            * Invalid types are skipped with a warning.

        Normalization:
        --------------
        1. Converts string keywords to lowercase for consistent matching.
        2. Compiles regex patterns if specified, applying the requested flags.
        3. Collects all normalized groups into a list for processing.

        Threshold handling:
        ------------------
        - Single-group: uses the threshold parameter or defaults to 2.
        - Multi-group: enforces 1 keyword per group, logging a warning if configuration
        is inconsistent or missing.
        - Ensures backward compatibility with existing rules.

        Matching logic:
        ---------------
        - Single-group:
            * Counts matching keywords in the line.
            * Returns True if the count >= threshold.
        - Multi-group:
            * Uses a recursive helper to ensure that at least one keyword from each
            group exists in the line.
            * Returns True only if all groups have at least one match.

        Parameters:
        -----------
        rule : HeuristicRule
            The heuristic rule object containing 'keywords' and optional 'threshold'.
        line : str
            The line of code being analyzed.
        ext : str
            File extension, for context (not used in this executor but part of signature).

        Returns:
        -------
        bool
            True if the line satisfies the keyword combination rule, False otherwise.

        Notes:
        ------
        - Designed to work for both simple keyword rules and complex multi-group rules.
        - Ensures that invalid configuration values do not crash the engine.
        - Logs warnings for configuration inconsistencies.
        """

        # Convert line to lowercase for case-insensitive matching
        line_lc = line.lower()

        # Retrieve keyword groups and optional thresholds from rule parameters
        groups = rule.parameters.get("keywords", [])  # Each group is a list of keywords or a regex
        thresholds = rule.parameters.get("threshold", [])

        # --- Normalize groups: convert all keywords to lowercase, compile regexes ---
        normalized_groups = []
        for g in groups:
            try:
                if isinstance(g, dict) and "regex" in g:
                    # Single regex dict as a group
                    flags = 0
                    if "flags" in g:
                        if "IGNORECASE" in g["flags"]:
                            flags |= re.IGNORECASE
                        if "MULTILINE" in g["flags"]:
                            flags |= re.MULTILINE
                    normalized_groups.append([{"regex": re.compile(g["regex"], flags)}])

                elif isinstance(g, list):
                    # List of keywords or regex dicts
                    normalized_subgroup = []
                    for kw in g:
                        if isinstance(kw, str):
                            normalized_subgroup.append(kw.lower())
                        elif isinstance(kw, dict) and "regex" in kw:
                            flags = 0
                            if "flags" in kw:
                                if "IGNORECASE" in kw["flags"]:
                                    flags |= re.IGNORECASE
                                if "MULTILINE" in kw["flags"]:
                                    flags |= re.MULTILINE
                            normalized_subgroup.append({"regex": re.compile(kw["regex"], flags)})
                        else:
                            if self.log:
                                self.log.write(f"Warning: Invalid keyword {kw} in group {g}, skipping")
                    normalized_groups.append(normalized_subgroup)

                elif isinstance(g, str):
                    # Single string keyword -> wrap in list
                    normalized_groups.append([g.lower()])

                else:
                    # Invalid type -> skip with warning
                    if self.log:
                        self.log.write(f"Warning: Invalid keyword group {g} in rule '{rule.id}', skipping")
                    continue

            except Exception as e:
                # Log any errors during normalization (e.g., invalid regex)
                if self.log:
                    self.log.write(f"Error: Failed to normalize keyword group {g} in rule '{rule.id}': {e}\n")
                self.die(f"Failed to normalize keyword group {g} in rule '{rule.id}': {e}")

        if not normalized_groups:
            self.die(f"Rule '{rule.id}' has no valid keyword groups after normalization.")

        # Determine number of groups after normalization
        amount = len(normalized_groups)

        # --- Single-group rule handling ---
        if amount == 1:
            group_size = len(normalized_groups[0])
            min_threshold = 1 if group_size == 1 else 2

            if not thresholds:
                # Default = 2, unless only 1 keyword is available
                thresholds = [min_threshold]
                if self.log and self.debug_mode:
                    self.log.write(
                        f"Info: Rule '{rule.id}': single group threshold automatically set to {thresholds[0]} "
                        f"(group size = {group_size})\n"
                    )

            elif thresholds[0] < 1:
                # Minimum threshold depends on group size
                if self.log and self.debug_mode:
                    self.log.write(
                        f"Warning: Rule '{rule.id}': single group threshold {thresholds[0]} increased to {min_threshold}\n"
                    )
                thresholds[0] = min_threshold

        # --- Multi-group rule handling ---
        else:
            overwrite = False
            if not thresholds:
                # No thresholds provided -> default to 1 per group
                thresholds = [1] * amount
            elif len(thresholds) != amount:
                # Mismatch in thresholds length -> overwrite
                overwrite = True
                reason = f"threshold length mismatch ({len(thresholds)} != {amount})"
            elif any(t != 1 for t in thresholds):
                # Multi-group rules always require threshold=1 per group
                overwrite = True
                reason = "threshold values != 1 in multi-group rule"

            if overwrite:
                # Log warning if thresholds were invalid and overwritten
                if self.log:
                    self.log.write(
                        f"Warning: Rule '{rule.id}': invalid multi-group threshold ({reason}), "
                        f"overwritten with {[1] * amount}\n"
                    )
                thresholds = [1] * amount

        # --- Collect matched lines for line- and file-scope rules ---
        def collect_matched_line(line: str) -> None:
            if len(line) > self.max_line_rule_hit_length:
                line = line[:self.max_line_rule_hit_length] + " [truncated]"
            if scope == "file":
                if line not in rule.matched_lines:
                    rule.matched_lines.append(line)
                    if not self.no_bail_out:
                        rule.sum_lines += 1
                        rule.sum_chars += len(line)
                        if rule.sum_lines >= self.max_lines_file_scan:
                            rule.bailout = True
                            raise BailoutException()
                        if rule.sum_chars >= self.max_chars_file_scan:
                            rule.bailout = True
                            raise BailoutException()
            else:
                rule.matched_lines.append(line)

        try:
            # --- Single-group matching ---
            if amount == 1:
                count = 0
                for item in normalized_groups[0]:
                    if isinstance(item, dict) and "regex" in item:
                        if item["regex"].search(line):
                            count += 1
                    else:
                        if item in line_lc:
                            count += 1

                result = count >= thresholds[0]
                if result:
                    collect_matched_line(line)
                return result

            # --- Multi-group recursive check ---
            def check_combination(idx: int) -> bool:
                """
                Recursively checks if at least one keyword from each group exists in the line.
                For multi-group rules, any 'threshold' in JSON is ignored; 1 keyword per group
                is required.
                idx: current group index
                """
                if idx >= len(normalized_groups):
                    return True  # all groups satisfied
                
                for item in normalized_groups[idx]:
                    if isinstance(item, dict) and "regex" in item:
                        if item["regex"].search(line):
                            if check_combination(idx + 1):
                                collect_matched_line(line)
                                return True
                    else:
                        if item in line_lc:
                            if check_combination(idx + 1):
                                collect_matched_line(line)
                                return True
                return False

            # Start recursion for multi-group rules
            return check_combination(0)
    
        except BailoutException:
            raise

    #
    # Example:
    # ----------
    # Input line (JS):
    #   line = 'var a = "x" + "y" + "z".concat("1", "2");'
    # Processing:
    #   1. '+=' count: 0
    #   2. '+' count: 2  → score += 2 * w_plus
    #   3. '.concat(' count: 1 → score += 1 * w_concat
    #   4. Escape sequences: none
    #   5. String literals: 5 short literals → score += 5 * w_short_string + extra for short_literals
    # Aggregated score = weighted sum of all signals
    # Output:
    #   result = True  # if score >= min_score
    #
    def _check_obfuscation_strings(self, rule: HeuristicRule, *, line: str, ext: str, scope: str) -> bool:
        r"""
        Detects string obfuscation caused by excessive or structured string construction.

        Works on a single line or the entire file content passed as a single string ('line').
        This heuristic combines multiple weak signals to reduce false positives on bundled or minified code.

        Signals considered:
        - Frequent string concatenation operators (+, +=)
        - Explicit concat/join usage
        - Hex or Unicode escape sequences (\xNN, \uNNNN)
        - Many short string literals ("a" + "b" + ...)
        - PowerShell-specific execution and decoding constructs

        Configuration parameters (optional):
            min_score (float): Minimum score to trigger (default: 12)
            min_string_literals (int): Minimum string literals contributing (default: 5)
            weights (dict): Weight per signal type

        Returns:
            bool: True if the aggregated score exceeds the configured threshold.
        """

        params = rule.parameters or {}

        min_score = float(params.get("min_score", 12))
        min_string_literals = int(params.get("min_string_literals", 5))

        weights = params.get("weights", {})
        w_plus = float(weights.get("plus", 1.0))
        w_concat = float(weights.get("concat", 2.0))
        w_escape = float(weights.get("escape", 2.5))
        w_short_string = float(weights.get("short_string", 0.5))
        w_ps_exec = float(weights.get("powershell_exec", 4.0))

        score = 0.0

        # Bailout - here, we do not apply bailout based on line count
        if scope == "file" and not self.no_bail_out:
            line_len = len(line)
            if line_len >= self.max_chars_file_scan:
                line = line[:self.max_chars_file_scan]
                rule.bailout = True
        
        # --- String concatenation operators ---
        plus_eq = line.count("+=")
        plus = line.count("+") - plus_eq  # avoid double counting
        score += plus_eq * (w_plus + 0.5)
        score += plus * w_plus

        # --- Language-specific string construction ---
        if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            score += len(re.findall(r"\.concat\s*\(", line)) * w_concat
        elif ext == ".py":
            score += len(re.findall(r"\.join\s*\(", line)) * w_concat

        # --- PowerShell decoding / execution ---
        if ext in (".ps1", ".psm1"):
            score += len(re.findall(r"-bxor", line, re.IGNORECASE)) * w_ps_exec
            score += len(re.findall(r"FromBase64String", line, re.IGNORECASE)) * w_ps_exec
            score += len(re.findall(r"\bIEX\b|\bInvoke-Expression\b", line, re.IGNORECASE)) * w_ps_exec
            score += line.count("`") * 0.5  # low-weight escape noise

        # --- Encoded escape sequences ---
        score += len(re.findall(r"\\x[0-9a-fA-F]{2}", line)) * w_escape
        score += len(re.findall(r"\\u[0-9a-fA-F]{4}", line)) * w_escape

        # --- String literals ---
        string_literals = re.findall(r"(?:'[^']*'|\"[^\"]*\")", line)
        short_literals = [s for s in string_literals if len(s) <= 4]

        # Contribute string literals to score only if enough are present
        if len(string_literals) >= min_string_literals:
            score += len(string_literals) * w_short_string
        if len(short_literals) >= min_string_literals:
            score += len(short_literals) * (w_short_string + 0.25)

        result = score >= min_score

        if result:
            if scope == "file":
                rule.matched_lines.append("[Check file – content omitted]")

        return result

    #
    # Check Obfuscation Vars - Rule Parameter Table: Conservative vs. Aggressive
    #
    # +----------------------+----------------+----------------+
    # | Parameter            | Conservative   | Aggressive     |
    # +----------------------+----------------+----------------+
    # | min_ratio            | 0.6            | 0.75           |
    # | entropy_threshold    | 3.5            | 3.8            |
    # | min_entropy_hits     | 0              | 5              |
    # | require_hex_prefix   | False          | True           |
    # | require_long_lines   | False          | True           |
    # | min_long_lines       | 0              | 3              |
    # | min_tokens           | 20             | 50             |
    # +----------------------+----------------+----------------+
    #
    # Notes:
    # - Conservative mode: detects obfuscation gently, reduces false positives on normal/minified code.
    # - Aggressive mode: targets packed/minified JS (npm modules), stronger thresholds to catch more obfuscated code.
    #
    def _check_obfuscation_vars(self, rule, *, line: str, ext: str, scope: str) -> bool:
        """
        Detects highly obfuscated or minified variable names in a file or a single line.

        This heuristic analyzes identifiers and computes a weighted obfuscation ratio based on:
        - Short variable names (<=2 characters)
        - Variables starting with obfuscation patterns (e.g., '_0x', '__', '_')
        - Random-looking variable names with high Shannon entropy
        - Optional presence of very long lines (>500 chars)

        The function aggregates several signals and applies thresholds (entropy hits, hex-prefixed vars,
        long lines) to reduce false positives. Works both for 'line' and 'file' scopes.

        Parameters:
            rule (HeuristicRule): Heuristic rule with parameters like min_ratio, entropy_threshold, etc.
            line (str): Input string (single line or entire file content)
            ext (str): File extension (for potential future extension-specific logic)

        Returns:
            bool: True if obfuscation exceeds thresholds, False otherwise
        """

        if (scope != "file"):
            if self.log:
                self.log.write(f"Error: Rule '{rule.id}': obfuscation_vars executor only works in 'file' scope\n")
            self.die(f"Rule '{rule.id}': obfuscation_vars executor only works in 'file' scope")

        # --- Load rule parameters with defaults ---
        p = rule.parameters or {}
        min_ratio = p.get("min_ratio", 0.75)
        min_entropy_hits = p.get("min_entropy_hits", 0)
        entropy_threshold = p.get("entropy_threshold", 3.8)
        require_hex_prefix = p.get("require_hex_prefix", False)
        require_long_lines = p.get("require_long_lines", False)
        min_long_lines = p.get("min_long_lines", 3)
        min_tokens = p.get("min_tokens", 50)

        # --- Constants / regex ---
        token_regex = r"\b[$_a-zA-Z][$\w]*\b"  # matches typical variable names


        # Bailout - here, we do not apply bailout based on line count
        if not self.no_bail_out:
            line_len = len(line)
            if (line_len >= self.max_chars_file_scan):
                line = line[:self.max_chars_file_scan]
                rule.bailout = True

        # --- Preprocessing ---
        lines = line.split("\n")
        long_line_count = sum(1 for l in lines if len(l) > 500)
        tokens = re.findall(token_regex, line)

        # Early exit if file/line too short
        if len(tokens) < min_tokens:
            return False

        # --- Scoring ---
        weighted_hits = 0.0
        entropy_hits = 0
        hex_hits = 0

        for t in tokens:
            if len(t) <= 2:
                weighted_hits += 0.8
            elif t.startswith("_0x"):
                weighted_hits += 1.2
                hex_hits += 1
            elif t.startswith("__"):
                weighted_hits += 0.5
            elif t.startswith("_"):
                weighted_hits += 0.3
            else:
                # Random-looking / high entropy variables
                if len(t) >= 5:
                    e = HeuristicEngine.entropy(t)
                    if e >= entropy_threshold:
                        weighted_hits += 1.0
                        entropy_hits += 1

        # --- Ratio calculation ---
        t_len = len(tokens)
        if t_len == 0:
            ratio = 1000
        else:
            ratio = weighted_hits / t_len

        # --- Threshold checks ---
        if ratio < min_ratio:
            return False
        if require_hex_prefix and hex_hits == 0:
            return False
        if require_long_lines and long_line_count < min_long_lines:
            return False
        if entropy_hits < min_entropy_hits:
            return False

        rule.matched_lines.append("[File content omitted]")

        return True
