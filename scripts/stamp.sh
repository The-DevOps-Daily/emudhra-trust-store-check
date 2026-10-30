#!/usr/bin/env bash
# Record the SHA-256 of the code and inputs and of every recorded result, so a
# result file can be matched to the code that produced it.
set -eu
cd "$(dirname "$0")/.."
{
  echo "# code and inputs"
  sha256sum stores.tsv lib/*.py scripts/*.py scripts/*.sh tools/*.c tools/get.js tools/gotls/*
  echo "# recorded results"
  sha256sum results/*
} > STAMPS.sha256
wc -l STAMPS.sha256
