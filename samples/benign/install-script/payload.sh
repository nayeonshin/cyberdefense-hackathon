#!/bin/sh
set -eu
echo "Checking for curl..."
command -v curl >/dev/null || { echo "curl is required"; exit 1; }
echo "Download the release from https://tool.example/releases and verify its checksum."
