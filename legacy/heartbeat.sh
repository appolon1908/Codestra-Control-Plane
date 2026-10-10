#!/usr/bin/env bash
set -euo pipefail
station="$1"
lease="/opt/codestra-dev/control-plane/leases/$station.json"
[ -f "$lease" ] || { echo NO_LEASE; exit 1; }
python3 - "$lease" <<'PY'
import json,sys,datetime
p=sys.argv[1]
d=json.load(open(p))
d["heartbeat_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
json.dump(d,open(p,"w"),indent=2)
PY
echo "HEARTBEAT_OK $station"
