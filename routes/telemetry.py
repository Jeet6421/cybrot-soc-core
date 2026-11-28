"""Suricata IDS ingest (PR 16): passive monitoring of the medical device network.

POST /api/ingest/suricata takes Suricata EVE JSON alert records (one object or a list). Only an ingest key whose
log source has the kind suricata_ids may post here. Records are normalized by hospital.normalize_suricata and then go
through the same checks, quotas, de-duplication, clock check and detection as /api/events.
Other EVE record types (flow, stats and so on) are counted as ignored."""
import os
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

import hospital

bp = Blueprint("telemetry", __name__)


def _soc():
    # app.py registers this blueprint after its helpers are defined, so importing it here at request time is safe.
    import app
    return app


@bp.post("/api/ingest/suricata")
def suricata():
    soc = _soc()
    ident = soc._require_ingest()
    c = soc.db()
    kind = c.execute("SELECT ingest_source_kind(%s) AS kind", (ident["log_source_id"],)).fetchone()["kind"]
    if kind != "suricata_ids":
        raise soc.Refuse(403, "this ingest key belongs to a log source that is not suricata_ids")
    raw_bytes = len(request.get_data(cache=True))
    body = request.get_json(force=True, silent=True)
    if body is None:
        raise soc.Refuse(400, "send a Suricata EVE JSON record or a list of them")
    records = body if isinstance(body, list) else [body]
    limits = soc._ingest_limits()
    if len(records) > limits["max_batch"]:
        raise soc.Refuse(413, f"send at most {limits['max_batch']} records per request")
    try:
        medical = hospital.medical_networks(os.environ.get("MEDICAL_NET_CIDRS"))
    except ValueError:
        raise soc.Refuse(503, "MEDICAL_NET_CIDRS is not a valid list of network ranges")
    events, ignored = [], 0
    for record in records:
        try:
            event = hospital.normalize_suricata(record, medical)
        except ValueError as exc:
            raise soc.Refuse(400, str(exc))
        if event is None:
            ignored += 1
        else:
            events.append(event)
    now_utc = datetime.now(timezone.utc)
    drifts = soc._stamp_events(events, ident, now_utc, suricata=True)
    soc._spend_ingest_quota(c, ident["tenant"], ident["log_source_id"], len(records), raw_bytes, limits)
    made_ids, stored, duplicates = soc._store_events(c, events)
    soc._record_skew(c, ident["log_source_id"], drifts)
    soc._record_current_audit(
        c, action="event.ingest", resource_type="event_batch", resource_id=None,
        resource_classification="telemetry",
        metadata={"source": "suricata", "record_count": len(records), "ignored": ignored, "stored": stored,
                  "duplicates": duplicates, "alerts_created": len(made_ids)})
    for alert_id in made_ids:
        soc._record_current_audit(
            c, action="alert.create", resource_type="alert", resource_id=alert_id,
            resource_classification="telemetry", metadata={"status": "new"})
    soc.commit()
    return jsonify(records=len(records), normalized=len(events), ignored=ignored, stored=stored,
                   duplicates=duplicates, alerts_created=len(made_ids))
