#!/usr/bin/env bash
# The keyed NVD sync behind nvd-cache.yml (#3417). It seeds odc-data from the
# last published NVD data image, so a normal day downloads only what NVD
# changed, and falls back to a full download, saying why, when there is no
# usable seed.
#
# Env: DC_VERSION, DC_SHA256 (the pinned dependency-check release and its zip
# digest), REGISTRY and NVD_IMAGE (the job's own data image name), NVD_API_KEY
# (optional), GITHUB_EVENT_NAME, and NVD_FULL_REBUILD=1 to force a full download.
# Needs the GHCR login step to have run first.
#
# What dependency-check 10.0.3 does, from its source (NvdApiDataSource, NAS):
# - with nvd.api.last.modified set it asks NVD only for records modified since
#   then, in one window of at most 120 days (NAS#L301-L310); unset, it
#   downloads everything;
# - it skips the update entirely, exit 0, when nvd.api.last.checked is under
#   nvd.api.check.validforhours (default 4) old (NAS#L286-L299), which a seed
#   can be, hence --nvdValidForHours 0 below;
# - it writes last.modified (the newest record it received, so a day when NVD
#   changed nothing leaves it where it was) and last.checked (now) only after a
#   whole update finishes (NAS#L372-L375, #L413-L416); a failed update leaves
#   both as they were and exits non-zero (8, UpdateException; App.java#L161-L182);
# - a per-record error is logged and never makes the exit non-zero
#   (NvdApiProcessor#L113-L122).
set -euo pipefail

: "${DC_VERSION:?}" "${DC_SHA256:?}" "${REGISTRY:?}" "${NVD_IMAGE:?}"
event_name="${GITHUB_EVENT_NAME:-}"

REBUILD_WEEKDAY=7            # Sunday (`date +%u`): the scheduled weekly full rebuild
REBUILD_AFTER_DAYS=7         # ... once the seed's last full build is this old
FULL_BUILD_CAP_DAYS=30       # past this a seed is never used, rebuild day or not
LAST_MODIFIED_CAP_DAYS=90    # well inside the 120-day window of one update
SIZE_FLOOR=104857600
STALE_SECONDS=259200         # 72 h (#3251)
MARKER=panopticon-seed.json

# #3224: `-e` too. Without it a failed download or a digest mismatch did not
# stop the step, and the unverified zip ran with the API key in its
# environment. The sync's own status is still captured below: `|| rc=$?` is a
# list `-e` does not abort.
sudo apt-get update
sudo apt-get install -y --no-install-recommends default-jre-headless unzip
curl -sfL --connect-timeout 5 --max-time 180 \
  "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip" \
  -o dc.zip
echo "${DC_SHA256}  dc.zip" | sha256sum -c -
unzip -q dc.zip     # -> ./dependency-check/

now="$(date -u +%s)"
weekday="$(date -u +%u)"
today="$(date -u +%F)"

# The database login is the tool's own public default, read from its jar.
login_error="::error::could not read the database login from dependency-check's jar"
props="$(unzip -p dependency-check/lib/dependency-check-core-*.jar dependencycheck.properties)" \
  || { echo "$login_error"; exit 1; }
db_user="$(printf '%s\n' "$props" | grep '^data\.user=')" || { echo "$login_error"; exit 1; }
db_user="${db_user#data.user=}"
db_pass="$(printf '%s\n' "$props" | grep '^data\.password=')" || { echo "$login_error"; exit 1; }
db_pass="${db_pass#data.password=}"

# db_property DIR KEY: `=<value>` for KEY's row in DIR's properties table (so
# `=` alone is a row with an empty value), nothing when there is no row, and a
# non-zero status when the database can't be read.
db_property() {
  local row
  row="$(java -cp "$(echo dependency-check/lib/h2-*.jar)" org.h2.tools.Shell \
    -url "jdbc:h2:file:./$1/odc;ACCESS_MODE_DATA=r" -user "$db_user" -password "$db_pass" \
    -sql "SELECT * FROM properties WHERE id='$2'")" || return 1
  case "$row" in
    *"$2 | "*) row="${row##*"$2 | "}"; printf '=%s\n' "${row%%[[:space:]]*}" ;;
  esac
}

# seed_time KEY: the seed's KEY value when it is a readable timestamp, else non-zero.
seed_time() {
  local value
  value="$(db_property seed "$1")" || return 1
  value="${value#=}"
  [ -n "$value" ] && date -u -d "$value" +%s > /dev/null 2>&1 || return 1
  printf '%s\n' "$value"
}

# The seed: our own image, pinned to the digest its tag points at right now,
# and used only when its marker says the same dependency-check made it and its
# last full build is recent enough. Anything else is a full download, by name.
seeded=0 full_build="$today" seed_checked_at="" reason=""
rm -rf odc-data seed
digest=""
if [ -n "${NVD_FULL_REBUILD:-}" ]; then
  reason="a full rebuild was requested"
elif ! digest="$(docker buildx imagetools inspect "${REGISTRY}/${NVD_IMAGE}:dc-${DC_VERSION}" \
                   --format '{{json .Manifest.Digest}}' 2>/dev/null)"; then
  reason="no seed image ${REGISTRY}/${NVD_IMAGE}:dc-${DC_VERSION}"
else
  digest="${digest//\"/}"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    reason="the seed image has no usable digest"
  else
    cid="$(docker create "${REGISTRY}/${NVD_IMAGE}@${digest}" seed)"
    mkdir seed
    docker cp "${cid}:/opt/odc-data/." seed/ || reason="could not copy the seed out of ${digest}"
    docker rm "$cid" > /dev/null || true
  fi
fi
if [ -z "$reason" ]; then
  marker="$(cat "seed/$MARKER" 2>/dev/null)" || marker=""
  seed_version="$(printf '%s\n' "$marker" | sed -n 's/.*"dc_version": *"\([^"]*\)".*/\1/p')"
  seed_full_build="$(printf '%s\n' "$marker" | sed -n 's/.*"full_build": *"\([^"]*\)".*/\1/p')"
  if [ -z "$marker" ]; then
    reason="the seed carries no $MARKER"
  elif [ "$seed_version" != "$DC_VERSION" ]; then
    reason="the seed was made by dependency-check ${seed_version:-?}, not ${DC_VERSION}"
  elif ! built_at="$(date -u -d "$seed_full_build" +%s 2>/dev/null)"; then
    reason="the seed's full_build is not a date: ${seed_full_build:-?}"
  else
    built_days="$(( (now - built_at) / 86400 ))"
    if [ "$built_days" -ge "$FULL_BUILD_CAP_DAYS" ]; then
      reason="the seed's last full build is ${built_days} days old (cap ${FULL_BUILD_CAP_DAYS})"
    elif [ "$built_days" -ge "$REBUILD_AFTER_DAYS" ] && [ "$event_name" = schedule ] \
         && [ "$weekday" = "$REBUILD_WEEKDAY" ]; then
      reason="weekly full rebuild (the seed's last full build is ${built_days} days old)"
    elif ! seed_modified="$(seed_time nvd.api.last.modified)"; then
      reason="the seed has no readable nvd.api.last.modified"
    elif [ "$(( (now - $(date -u -d "$seed_modified" +%s)) / 86400 ))" -ge "$LAST_MODIFIED_CAP_DAYS" ]; then
      reason="the seed's nvd.api.last.modified is over ${LAST_MODIFIED_CAP_DAYS} days old"
    elif ! seed_checked="$(seed_time nvd.api.last.checked)"; then
      reason="the seed has no readable nvd.api.last.checked"
    else
      seeded=1 full_build="$seed_full_build"
      seed_checked_at="$(date -u -d "$seed_checked" +%s)"
    fi
  fi
fi
if [ "$seeded" = 1 ]; then
  mv seed odc-data
  echo "seeded from ${REGISTRY}/${NVD_IMAGE}@${digest} (last full build ${full_build}, nvd.api.last.modified ${seed_modified})"
else
  rm -rf seed
  mkdir odc-data
  echo "::notice::${reason}: full download"
fi

# #2508 (run-14 OPS-2602119269): a sync KILLED by `timeout` (124, or 137 after
# SIGKILL) left the database mid-write, and a partial file can clear the size
# floor, so that status always fails. Any other non-zero status means the update
# failed (10.0.3 exits 0 through per-record errors, see the top). On a seeded run
# that leaves yesterday's database looking fresh, so it fails too. On a full
# download it is still let through to the checks below, which refuse it: over an
# empty directory a failed update leaves nvd.api.last.modified unset.
rc=0
timeout 3000 ./dependency-check/bin/dependency-check.sh --updateonly --data odc-data \
  --nvdValidForHours 0 ${NVD_API_KEY:+--nvdApiKey "$NVD_API_KEY"} || rc=$?
case "$rc" in
  0) ;;
  124|137) echo "::error::updateonly was killed by the 3000 s deadline (rc=$rc); not publishing a partial DB"; exit 1 ;;
  *) if [ "$seeded" = 1 ]; then
       echo "::error::updateonly failed (rc=$rc) over the seed; the database is the seed's, not today's; not publishing"
       exit 1
     fi
     echo "::warning::updateonly returned non-zero (rc=$rc) on a full download; verifying the DB below" ;;
esac
chmod -R a+rX odc-data
test -f odc-data/odc.mv.db || { echo "::error::NVD database (odc.mv.db) was not produced"; exit 1; }
size="$(stat -c%s odc-data/odc.mv.db)"
echo "odc.mv.db: $((size / 1024 / 1024)) MiB"
[ "$size" -gt "$SIZE_FLOOR" ] || { echo "::error::NVD DB only $((size / 1024 / 1024)) MiB — sync likely incomplete"; exit 1; }

# #3251: the size floor shows a database exists, not that this update finished.
# Over an empty directory a failed update leaves nvd.api.last.modified unset, and
# an old value means the feed stopped moving. Either way, don't publish.
modified="$(db_property odc-data nvd.api.last.modified)" \
  || { echo "::error::could not read nvd.api.last.modified from the NVD database"; exit 1; }
case "$modified" in
  "") echo "::error::NVD DB has no nvd.api.last.modified — the update did not finish; not publishing"; exit 1 ;;
  "=") echo "::error::NVD DB has an empty nvd.api.last.modified — not publishing"; exit 1 ;;
esac
modified="${modified#=}"
modified_at="$(date -u -d "$modified" +%s)" \
  || { echo "::error::nvd.api.last.modified is not a timestamp: $modified"; exit 1; }
age_seconds="$(( now - modified_at ))"
echo "nvd.api.last.modified: $modified ($(( age_seconds / 3600 )) h old)"
# An hour of clock skew is allowed; further ahead than that, the value can't be right.
[ "$age_seconds" -ge -3600 ] || { echo "::error::nvd.api.last.modified is in the future: $modified"; exit 1; }
[ "$age_seconds" -le "$STALE_SECONDS" ] || { echo "::error::NVD DB is over 72 h old — not publishing stale data"; exit 1; }

# #3417: the same guard over a seed. A seed's last.modified is recent whether or
# not today's update ran, and stays put on a day NVD changed nothing. What a
# finished update always moves is last.checked, so a seeded database is
# published only when that moved past the seed's.
if [ "$seeded" = 1 ]; then
  checked="$(db_property odc-data nvd.api.last.checked)" \
    || { echo "::error::could not read nvd.api.last.checked from the NVD database"; exit 1; }
  checked="${checked#=}"
  checked_at="$(date -u -d "${checked:-none}" +%s 2>/dev/null)" || checked_at=""
  if [ -z "$checked_at" ] || [ "$checked_at" -le "$seed_checked_at" ]; then
    echo "::error::nvd.api.last.checked (${checked:-unset}) did not move past the seed's (${seed_checked}); the update did not run; not publishing"
    exit 1
  fi
  echo "nvd.api.last.checked: ${checked} (seed: ${seed_checked})"
fi

printf '{"dc_version": "%s", "full_build": "%s"}\n' "$DC_VERSION" "$full_build" > "odc-data/$MARKER"
chmod a+r "odc-data/$MARKER"
echo "marker: dependency-check ${DC_VERSION}, last full build ${full_build}"
