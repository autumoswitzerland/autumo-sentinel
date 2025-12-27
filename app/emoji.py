#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
#
# autumo Sentinel – Multi-Stage Supply-Chain Malware Scanner & Code Forensics
# Version 3.0.0 | Copyright (c) 2025 autumo GmbH
#
# DESCRIPTION:
#   Emojis. 
#
# LICENSE:
#   SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-commercial
#   Dual license: GPL-3.0 (https://www.gnu.org/licenses/gpl-3.0.en.html)
#                 or commercial (contact autumo GmbH)
#
# ------------------------------------------------------------------------------


import platform

SYSTEM = platform.system()

# Symbol definitions per platform
if SYSTEM == "Darwin":
    # macOS: real emojis
    SCAN = "🔍 "
    GLOBAL = "🌍 "
    SUCCESS = "✅ "
    ERROR = "❌ "
    WARNING = "⚠️  "
    INFO = "ℹ️  "
    DISK = "💾 "
    ORDER = "🔢 "
    ENGINE = "📜 "
    LOGO = "👾⚡️ "
else:
    # Windows and Linux: only safe ASCII/Unicode characters
    SCAN = ""
    GLOBAL = ""
    SUCCESS = "[√] "
    ERROR = "[x] "
    WARNING = "[!] "
    INFO = "[i] "
    DISK = ""
    ORDER = ""
    ENGINE = ""
    LOGO = ""

# Functions
def scan() -> str:
    return SCAN

def glob() -> str:
    return GLOBAL

def ok() -> str:
    return SUCCESS

def err() -> str:
    return ERROR

def warn() -> str:
    return WARNING

def info() -> str:
    return INFO

def disk() -> str:
    return DISK

def order() -> str:
    return ORDER

def engine() -> str:
    return ENGINE

def logo() -> str:
    return LOGO
