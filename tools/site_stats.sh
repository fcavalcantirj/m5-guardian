#!/usr/bin/env bash
# Website numbers from Vercel Web Analytics (read-only): visitors, page views, top pages, referrers,
# countries, devices, the install-page counts (guardian_install events by step, e.g. update:done) and the
# clicks on links that leave the site (outbound_click by target, e.g. repo#build-and-install).
# Usage: tools/site_stats.sh [days]        (default 30)
# Needs: the Vercel CLI logged in to the project's team, and .vercel/project.json (vercel link) at the
# repository root, or VERCEL_PROJECT_ID. Counts are browser-side: a visitor who blocks the analytics
# script is not counted. Never run by CI.
set -euo pipefail
cd "$(dirname "$0")/.."

days="${1:-30}"
[[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 ]] || { echo "usage: tools/site_stats.sh [days]" >&2; exit 2; }
project="${VERCEL_PROJECT_ID:-}"
if [[ -z "$project" ]]; then
  [[ -f .vercel/project.json ]] || { echo "site_stats: no .vercel/project.json (run vercel link) and no VERCEL_PROJECT_ID" >&2; exit 2; }
  project="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["projectId"])' .vercel/project.json)"
fi
# The query API counts whole UTC days (an until inside today is cut back to 00:00), so ask for whole days
# ending at tomorrow 00:00 UTC.
since="$(python3 -I -c 'import datetime,sys; t=datetime.datetime.now(datetime.timezone.utc).date(); print((t-datetime.timedelta(days=int(sys.argv[1])-1)).isoformat()+"T00:00:00Z")' "$days")"
until="$(python3 -I -c 'import datetime; t=datetime.datetime.now(datetime.timezone.utc).date(); print((t+datetime.timedelta(days=1)).isoformat()+"T00:00:00Z")')"
query="projectId=$project&since=$since&until=$until"

# vercel api prints a hint line before the JSON; keep the JSON object only.
api() { vercel api "$1" --raw 2>/dev/null | python3 -I -c 'import sys; s=sys.stdin.read(); print(s[s.index("{"):s.rindex("}")+1])'; }

echo "M5 Guardian website, last $days days (since $since)"
api "/v1/query/web-analytics/visits/count?$query" | python3 -I -c '
import json,sys; d=json.load(sys.stdin)["data"]; print("  visitors %s   page views %s" % (d.get("visitors",0), d.get("pageviews",0)))'

table() { # $1 endpoint, $2 dimension, $3 title, $4 limit, $5 label for an empty value, $6 event name (events only)
  local filter=""
  [[ -n "${6:-}" ]] && filter="&filter=$(python3 -I -c 'import sys,urllib.parse; print(urllib.parse.quote("eventName eq %r" % sys.argv[1]))' "$6")"
  api "/v1/query/web-analytics/$1/aggregate?$query&by=$2&limit=$4$filter" | python3 -I -c '
import json,sys
dim,title=sys.argv[1],sys.argv[2]; rows=json.load(sys.stdin).get("data",[])
print(f"\n{title}")
if not rows: print("  (none)")
for r in sorted(rows,key=lambda r:-r.get("count",r.get("pageviews",0))):
    n=r.get("count",r.get("pageviews",0)); print("  %6s  %5s visitors  %s" % (n, r.get("visitors",0), r.get(dim) or sys.argv[3]))' "$2" "$3" "$5"
}
table visits requestPath "Pages" 10 "(none)"
table visits referrerHostname "Referrers" 10 "(direct)"
table visits country "Countries" 10 "(unknown)"
table visits deviceType "Devices" 5 "(unknown)"
table events "eventData/step" "Install page (guardian_install by step: <action>:<result>)" 50 "(no step: sent before 2026-11-24)" guardian_install
table events "eventData/target" "Links out (outbound_click by target)" 20 "(no target)" outbound_click
