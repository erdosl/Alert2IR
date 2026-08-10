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

for required_path in infra/puppet config/sysmon/alert2ir-sysmon.xml; do
  if ! git -C "$repository_root" cat-file -e "${commit}:${required_path}"; then
    echo "Error: required path '$required_path' is absent from commit $commit." >&2
    exit 1
  fi
done

if [[ ! -d $output_directory ]]; then
  echo "Error: output directory '$output_directory' does not exist." >&2
  exit 1
fi

output_directory=$(cd -- "$output_directory" && pwd)
short_commit=${commit:0:12}
artifact_path="$output_directory/alert2ir_ws02-${short_commit}.zip"

if [[ -e $artifact_path || -L $artifact_path ]]; then
  echo "Error: refusing to overwrite existing artifact '$artifact_path'." >&2
  exit 1
fi

temporary_directory=$(mktemp -d "$output_directory/.alert2ir_ws02-build.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT
environment_root="$temporary_directory/environment"
temporary_artifact_path="$temporary_directory/alert2ir_ws02-${short_commit}.zip"
mkdir -p "$environment_root/modules/profile/files/sysmon"

git -C "$repository_root" archive "${commit}:infra/puppet" | tar -x -C "$environment_root"
git -C "$repository_root" show "${commit}:config/sysmon/alert2ir-sysmon.xml" \
  > "$environment_root/modules/profile/files/sysmon/alert2ir-sysmon.xml"

commit_timestamp=$(git -C "$repository_root" show -s --format=%ct "$commit")
python3 - "$environment_root" "$temporary_artifact_path" "$commit_timestamp" <<'PY'
import datetime
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1])
artifact = pathlib.Path(sys.argv[2])
timestamp = datetime.datetime.fromtimestamp(int(sys.argv[3]), datetime.timezone.utc)
zip_time = max(timestamp, datetime.datetime(1980, 1, 1, tzinfo=datetime.timezone.utc)).timetuple()[:6]

with zipfile.ZipFile(artifact, "x", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            relative += "/"
        info = zipfile.ZipInfo(relative, zip_time)
        info.create_system = 3
        info.external_attr = (0o40755 if path.is_dir() else 0o100644) << 16
        if path.is_dir():
            archive.writestr(info, b"")
        else:
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
PY

artifact_sha256=$(sha256sum "$temporary_artifact_path" | awk '{print $1}')
sysmon_sha256=$(sha256sum "$environment_root/modules/profile/files/sysmon/alert2ir-sysmon.xml" | awk '{print $1}')

if ! mv -n -- "$temporary_artifact_path" "$artifact_path" \
  || [[ -e $temporary_artifact_path || -L $temporary_artifact_path ]]; then
  echo "Error: refusing to overwrite existing artifact '$artifact_path'." >&2
  exit 1
fi

printf 'Git commit: %s\n' "$commit"
printf 'Artifact path: %s\n' "$artifact_path"
printf 'Artifact SHA-256: %s\n' "$artifact_sha256"
printf 'Staged Sysmon XML SHA-256: %s\n' "$sysmon_sha256"
