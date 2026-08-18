#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <git-ref> [output-directory]" >&2
}

if (( $# < 1 || $# > 2 )); then
  usage
  exit 2
fi

ref=$1
output_directory=${2:-.}
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(git -C "$script_directory" rev-parse --show-toplevel)

if ! commit=$(git -C "$repository_root" rev-parse --verify "${ref}^{commit}"); then
  echo "Error: '$ref' does not resolve to a Git commit." >&2
  exit 1
fi

app_path=integrations/splunk/alert2ir_delivery
if ! git -C "$repository_root" cat-file -e "${commit}:${app_path}"; then
  echo "Error: '$app_path' is absent from commit $commit." >&2
  exit 1
fi

if [[ ! -d $output_directory ]]; then
  echo "Error: output directory '$output_directory' does not exist." >&2
  exit 1
fi

output_directory=$(cd -- "$output_directory" && pwd)
short_commit=${commit:0:12}
artifact_path="$output_directory/alert2ir_delivery-${short_commit}.tgz"
if [[ -e $artifact_path || -L $artifact_path ]]; then
  echo "Error: refusing to overwrite existing artifact '$artifact_path'." >&2
  exit 1
fi

temporary_directory=$(mktemp -d "$output_directory/.alert2ir-splunk-build.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT
temporary_artifact="$temporary_directory/alert2ir_delivery-${short_commit}.tgz"

git -C "$repository_root" archive \
  --format=tar \
  --prefix=alert2ir_delivery/ \
  "${commit}:${app_path}" \
  | gzip -n > "$temporary_artifact"

if ! mv -n -- "$temporary_artifact" "$artifact_path" \
  || [[ -e $temporary_artifact || -L $temporary_artifact ]]; then
  echo "Error: refusing to overwrite existing artifact '$artifact_path'." >&2
  exit 1
fi

artifact_sha256=$(sha256sum "$artifact_path" | awk '{print $1}')
printf 'Git commit: %s\n' "$commit"
printf 'Artifact path: %s\n' "$artifact_path"
printf 'Artifact SHA-256: %s\n' "$artifact_sha256"
