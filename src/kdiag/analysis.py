import re
from datetime import datetime, timedelta, timezone

from kdiag.util import utc_now


DURATION_RE = re.compile(r"^([1-9][0-9]*)(m|h|d)$")
MAX_INCIDENT_SECONDS = 30 * 24 * 60 * 60


def parse_utc_timestamp(value, field_name="timestamp"):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as error:
            raise ValueError("{0} must be an ISO-8601 UTC timestamp".format(field_name)) from error
    else:
        raise ValueError("{0} must be an ISO-8601 UTC timestamp".format(field_name))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("{0} must include a UTC offset".format(field_name))
    return parsed.astimezone(timezone.utc)


def format_utc_timestamp(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_incident_duration(value):
    match = DURATION_RE.fullmatch(str(value or ""))
    if not match:
        raise ValueError("incident-since must use <n>m, <n>h or <n>d")
    amount = int(match.group(1))
    multiplier = {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = amount * multiplier
    if seconds > MAX_INCIDENT_SECONDS:
        raise ValueError("incident window must not exceed 30 days")
    return seconds


def resolve_analysis_window(
    purpose,
    incident_since=None,
    incident_start=None,
    incident_end=None,
    now=None,
):
    if purpose not in ("check", "incident"):
        raise ValueError("analysis purpose must be check or incident")
    if purpose == "check":
        if incident_since or incident_start or incident_end:
            raise ValueError("incident window is only valid with purpose=incident")
        return {"purpose": "check", "incident_start": None, "incident_end": None}
    if incident_since and incident_start:
        raise ValueError("incident-since and incident-start are mutually exclusive")
    if incident_since and incident_end:
        raise ValueError("incident-end cannot be combined with incident-since")
    current = parse_utc_timestamp(now or utc_now(), "current time")
    if incident_since:
        end = current
        start = end - timedelta(seconds=parse_incident_duration(incident_since))
    elif incident_start:
        start = parse_utc_timestamp(incident_start, "incident-start")
        end = parse_utc_timestamp(incident_end, "incident-end") if incident_end else current
    else:
        raise ValueError("purpose=incident requires an explicit incident window")
    if start >= end:
        raise ValueError("incident-start must be earlier than incident-end")
    if (end - start).total_seconds() > MAX_INCIDENT_SECONDS:
        raise ValueError("incident window must not exceed 30 days")
    return {
        "purpose": "incident",
        "incident_start": format_utc_timestamp(start),
        "incident_end": format_utc_timestamp(end),
    }
