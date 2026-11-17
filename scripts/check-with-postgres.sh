#!/usr/bin/env bash
set -euo pipefail
# A disposable, socket-only cluster; never connects to an application database.
pg_bin="${STUHELPER_TEST_PG_BIN:-}"
if [[ -z "$pg_bin" ]] && command -v pg_config >/dev/null 2>&1; then
  candidate="$(pg_config --bindir 2>/dev/null || true)"
  if [[ -n "$candidate" && -x "$candidate/initdb" && -x "$candidate/pg_ctl" && -x "$candidate/postgres" ]]; then
    pg_bin="$candidate"
  fi
fi
if [[ -z "$pg_bin" ]] && command -v initdb >/dev/null 2>&1; then
  candidate="$(dirname "$(command -v initdb)")"
  if [[ -x "$candidate/initdb" && -x "$candidate/pg_ctl" && -x "$candidate/postgres" ]]; then
    pg_bin="$candidate"
  fi
fi
if [[ -z "$pg_bin" ]] && command -v dpkg-query >/dev/null 2>&1; then
  pg_package="$(dpkg-query -W -f='${Depends}' postgresql 2>/dev/null | grep -oE 'postgresql-[0-9]+' | head -n 1 || true)"
  if [[ -n "$pg_package" ]]; then
    pg_bin="/usr/lib/postgresql/${pg_package#postgresql-}/bin"
  fi
fi
if [[ -z "$pg_bin" ]]; then
  echo "ERROR: PostgreSQL server binaries (initdb/pg_ctl/postgres) not found; set STUHELPER_TEST_PG_BIN" >&2
  exit 1
fi
export STUHELPER_TEST_PG_BIN="$pg_bin"
"$pg_bin/postgres" --version
test -x "$pg_bin/initdb"
task_dir="$(mktemp -d /tmp/stuhelper-media-check.XXXXXX)"
cleanup() {
  "$pg_bin/pg_ctl" -D "$task_dir/data" -m immediate stop >/dev/null 2>&1 || true
  case "$task_dir" in /tmp/stuhelper-media-check.*) rm -rf -- "$task_dir" ;; esac
}
trap cleanup EXIT INT TERM
mkdir "$task_dir/socket"
"$pg_bin/initdb" -D "$task_dir/data" --auth-local=trust --auth-host=reject --no-locale --encoding=UTF8 >/dev/null
"$pg_bin/pg_ctl" -D "$task_dir/data" -l "$task_dir/server.log" -o "-h '' -k $task_dir/socket -p 55439" -w start >/dev/null
export STUHELPER_MEDIA_TEST_DSN="host=$task_dir/socket port=55439 user=$(id -un) dbname=postgres sslmode=disable"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf 'Media source: `%s`\n\n' "$(git rev-parse HEAD)"
    printf 'Storage source dependency: `%s`\n\n' "$(GOWORK=off go list -m github.com/StuHelper/stuhelper-storage)"
    printf 'Database: `%s`; GOWORK=off; isolated socket-only test cluster.\n' "$("$pg_bin/postgres" --version)"
  } >> "$GITHUB_STEP_SUMMARY"
fi
make check
