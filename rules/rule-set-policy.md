## Rule Set Policy & Editions

autumo Sentinel is released under **dual licensing**:

### Community / Open Version
- **License:** GPLv3
- **Rules Included:** Low severity rules (examples only)
- **Purpose:** Demonstrate scanner mechanics, safe experimentation, and rule writing.

### Commercial / Full Version
- **License:** autumo Products General License (v1.0)
- **Rules Included:** Medium & High severity rules
- **Purpose:** Authorized users get production-ready heuristics for CI/CD, enterprise, or security teams.
- **Note:** Commercial rules are **not included** in the public repository to protect proprietary heuristics.
- **Contact / Ordering:** info@autumo.com or https://autumo.com

### Low Severity Rules (Community)

| ID | Name | Scope | Type | Severity | Heuristic Threshold | Only If No Match |
|----|------|-------|------|----------|-------------------|-----------------|
| excessive_string_concatenation | Excessive string concatenation | file | obfuscation_strings | low | 3 | true |
| js_string_reconstruction | JS string reconstruction primitive | line | keyword_combination | low | 3 | true |
| js_binary_buffer_primitive | JS binary buffer primitive | line | keyword_combination | low | 3 | true |
| js_btoa_eval | btoa combined with eval | line | keyword_combination | low | 3 | true |
| js_aes128cbc_eval | AES-128-CBC combined with eval | line | keyword_combination | low | 3 | true |
| js_aes256cbc_eval | AES-256-CBC combined with eval | line | keyword_combination | low | 3 | true |
| long_string_generic | Unusually long string | line | string_length | low | 5 | true |
| obfuscated_variable_names | Highly obfuscated variable names | file | obfuscation_vars | low | 3 | true |
| suspicious_env_var_usage | Suspicious environment variable usage | line | keyword_combination | low | 2 | true |

### Medium Severity Rules (Commercial Version)

Medium severity rules focus on multi-step suspicious behavior, including:
- dynamic code execution
- script-based persistence mechanisms
- environment and loader manipulation
- network-assisted execution chains

These rules are **not included in the public repository**.

### High Severity Rules (Commercial Version)

High severity rules detect high-confidence malicious behavior, such as:
- encoded or compressed payload execution
- privilege escalation and capability abuse
- dynamic loader and runtime manipulation
- immediate execution of decoded payloads

Exact rule definitions are part of the **commercial edition only**.
