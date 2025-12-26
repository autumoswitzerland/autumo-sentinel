## Rule Parameters

The `parameters` object is the primary configuration surface of a rule.
Different rule types accept different parameter sets, depending on their detection logic.

### String Length Detection `string_length`

Used to flag unusually long strings or encoded payloads.

| Parameter	| Type | Description |
|-----------|------|-------------|
| `min_length` | integer | Minimum line length required before the rule can trigger |

- **Scope:** line

### base64 Payload Detection `base64_suspect`

Detects Base64-like payloads without decoding content.

| Parameter	| Type | Description |
|-----------|------|-------------|
| `min_length` | integer | Minimum length before Base64 pattern matching is applied |

- **Scope:** line

### HEX Payload Detection `hex_suspect`

Detects hexadecimal payload fragments.

| Parameter	| Type | Description |
|-----------|------|-------------|
| `min_length` | integer | Minimum line length before hex validation |

- **Scope:** line

### Path Access Detection `path_access`

Detects suspicious access to sensitive paths.

| Parameter	| Type | Description |
|-----------|------|-------------|
| `paths` | list of strings | Substring match against code lines |

- **Scope:** line
- Simple substring matching
- No regular expressions

### Keyword Combination Rules `keyword_combination`

Detects semantic combinations of suspicious keywords or patterns.

| Parameter	| Type | Description |
|-----------|------|-------------|
| `keywords` | list | Keyword groups or regex patterns |
| `threshold` | list of integers | Required matches per keyword group |

- **Scope**: line and file
- **Single keyword group:** 
    - At least **1 keyword** must match by default if the group contains only a single keyword or regex.  
    - If the group contains multiple keywords, at least **2 keywords** must match by default.  
- **Multiple keyword groups:** at least **1 keyword per group** must match  
- Invalid thresholds are automatically corrected (single-group thresholds cannot go below 1 or 2 depending on group size)

#### Using Regular Expressions

Keyword groups may contain **plain keywords** or **regular expression patterns**.
Regex patterns allow more flexible matching, such as variable names, obfuscation prefixes,
or dynamically generated identifiers.

##### Regex Pattern Syntax

Regex patterns are defined using an object with a `regex` field:

```json
{
  "keywords": [
    [{"regex": "obf_[a-z]+"}]
  ]
}
```

This pattern matches identifiers like `obf_a`, `obf_xyz`, etc.

##### Regex Flags

Optional regex flags can be specified using a `flags` array.

Supported flags:

- `IGNORECASE` – case-insensitive matching  
- `MULTILINE` – multiline mode (`^` and `$` match line boundaries)

Example with flags:

```json
{
  "keywords": [
    [{"regex": "eval\\s*\\(", "flags": ["IGNORECASE"]}]
  ]
}
```

##### Mixed Keyword Groups (Strings + Regex)

Keyword groups may freely mix strings and regex patterns.

Example:

```json
{
  "keywords": [
    ["eval", "exec"],
    [{ "regex": "base64", "flags": ["IGNORECASE"] }],
    [{ "regex": "obf_[a-z]+" }]
  ]
}
```

Matching logic:

- Group 1: requires **one of** `eval` or `exec`
- Group 2: requires a case-insensitive match of `base64`
- Group 3: requires a variable matching `obf_[a-z]+`

All keyword groups must match for the rule to trigger.

##### Notes

- Regex patterns are applied as **search matches**, not full-line matches.
- Invalid regex patterns will cause the rule to be rejected.
- Threshold values are ignored for multi-group rules (always 1 per group).

### String Obfuscation Detection `obfuscation_strings`

Scores multiple weak indicators of string obfuscation.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_score` | float | 12.0 | Minimum total score required |
| `min_string_literals` | integer | 5 | Minimum contributing literals |
| `weights.plus` | float | 1.0 | `+` and `+=` operators |
| `weights.concat` | float | 2.0 | `.concat()` / `.join()` |
| `weights.escape` | float | 2.5 | `\xNN`, `\uNNNN` |
| `weights.short_string` | float | 0.5 | Short string literals |
| `weights.powershell_exec` | float | 4.0 | PowerShell execution primitives |

- **Scope:** line and file
- Scores are aggregated
- Designed to reduce false positives on bundled or minified code

### Variable Obfuscation Detection `obfuscation_vars`

Detects heavily obfuscated or minified variable naming.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_ratio` | float | 0.75 | Required obfuscation ratio |
| `entropy_threshold` | float | 3.8 | Shannon entropy limit |
| `min_entropy_hits` | integer | 0 | Required high-entropy identifiers |
| `require_hex_prefix` | boolean | false | Require `_0x*` variables |
| `require_long_lines` | boolean | false | Enforce long-line presence |
| `min_long_lines` | integer | 3 | Required long lines |
| `min_tokens` | integer | 50 | Minimum identifiers in file |

- **Scope:** file
- Evaluated only on full file content
- Intended to avoid false positives on normal libraries

---
&copy; 2025 autumo GmbH
