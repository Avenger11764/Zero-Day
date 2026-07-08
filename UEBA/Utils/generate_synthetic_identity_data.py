#!/usr/bin/env python3
"""
Synthetic Identity/Device Event Generator — v2
===============================================
Generates fake-but-plausible login/session telemetry for the UEBA risk model
in the Zero-Day Detection FYP.

v2 changes:
  - 25 cities across 20 countries (was 10 cities, 8 countries)
  - Fixed DST offsets for June (London BST +1, New York EDT -4, Sydney AEST +10)
  - new_country_odd_hour now checks user-local hour, not UTC hour
  - allocate_any() IPs are now tied to a real random city (no IP-geo mismatch)
  - 10 anomaly types (was 5): +off_hours_access, +dormant_account_reactivation,
    +data_to_personal_cloud, +cookie_reuse, +unusual_login_frequency
  - Impossible travel: 15–120 min gap (was 15–45), more variety
  - Power-law user distribution (some users 5x more active than others)
  - More activities: 16 (was 8)
  - Added device_type, session_id, data_size_mb, role fields
  - verify() function fixed (_prev_city field no longer phantom)
  - Reproducible via --seed (uuid uses deterministic randomness now)

Usage:
    python3 generate_synthetic_identity_data.py --users 20 --events 20000 --anomaly-ratio 0.08

Outputs:
    synthetic_identity_events.json    (same schema, 10 anomaly types)
    synthetic_identity_events.csv
"""

import argparse
import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2

# ---- Reference data pools ---------------------------------------------------

CITIES = [
    # (city, country_code, lat, lon)
    ("Delhi", "IN", 28.6139, 77.2090),
    ("Mumbai", "IN", 19.0760, 72.8777),
    ("Bengaluru", "IN", 12.9716, 77.5946),
    ("London", "GB", 51.5074, -0.1278),
    ("New York", "US", 40.7128, -74.0060),
    ("Moscow", "RU", 55.7558, 37.6173),
    ("Lagos", "NG", 6.5244, 3.3792),
    ("Singapore", "SG", 1.3521, 103.8198),
    ("Sao Paulo", "BR", -23.5505, -46.6333),
    ("Sydney", "AU", -33.8688, 151.2093),
    ("Tokyo", "JP", 35.6762, 139.6503),
    ("Seoul", "KR", 37.5665, 126.9780),
    ("Dubai", "AE", 25.2048, 55.2708),
    ("Berlin", "DE", 52.5200, 13.4050),
    ("Paris", "FR", 48.8566, 2.3522),
    ("Toronto", "CA", 43.6532, -79.3832),
    ("Mexico City", "MX", 19.4326, -99.1332),
    ("Cairo", "EG", 30.0444, 31.2357),
    ("Nairobi", "KE", -1.2921, 36.8219),
    ("Jakarta", "ID", -6.2088, 106.8456),
    ("Bangkok", "TH", 13.7563, 100.5018),
    ("Buenos Aires", "AR", -34.6037, -58.3816),
    ("Madrid", "ES", 40.4168, -3.7038),
    ("Rome", "IT", 41.9028, 12.4964),
    ("Amsterdam", "NL", 52.3676, 4.9041),
]

# Timezone offsets for June (Northern-hemisphere DST applied)
# London BST = +1, New York EDT = -4, Sydney AEST = +10 (DST starts Oct)
CITY_TZ = {
    "Delhi": "Asia/Kolkata", "Mumbai": "Asia/Kolkata", "Bengaluru": "Asia/Kolkata",
    "London": "Europe/London", "New York": "America/New_York",
    "Moscow": "Europe/Moscow", "Lagos": "Africa/Lagos",
    "Singapore": "Asia/Singapore", "Sao Paulo": "America/Sao_Paulo",
    "Sydney": "Australia/Sydney",
    "Tokyo": "Asia/Tokyo", "Seoul": "Asia/Seoul", "Dubai": "Asia/Dubai",
    "Berlin": "Europe/Berlin", "Paris": "Europe/Paris",
    "Toronto": "America/Toronto", "Mexico City": "America/Mexico_City",
    "Cairo": "Africa/Cairo", "Nairobi": "Africa/Nairobi",
    "Jakarta": "Asia/Jakarta", "Bangkok": "Asia/Bangkok",
    "Buenos Aires": "America/Argentina/Buenos_Aires",
    "Madrid": "Europe/Madrid", "Rome": "Europe/Rome", "Amsterdam": "Europe/Amsterdam",
}

# UTC offsets for June 2026 (DST-aware for northern hemisphere)
TZ_OFFSET = {
    "Asia/Kolkata": 5.5,
    "Europe/London": 1,                  # BST
    "America/New_York": -4,              # EDT
    "Europe/Moscow": 3,
    "Africa/Lagos": 1,
    "Asia/Singapore": 8,
    "America/Sao_Paulo": -3,
    "Australia/Sydney": 10,              # AEST
    "Asia/Tokyo": 9,
    "Asia/Seoul": 9,
    "Asia/Dubai": 4,
    "Europe/Berlin": 2,                  # CEST
    "Europe/Paris": 2,                   # CEST
    "America/Toronto": -4,               # EDT
    "America/Mexico_City": -5,           # CST (no DST in Mexico since 2023)
    "Africa/Cairo": 3,                   # EEST
    "Africa/Nairobi": 3,
    "Asia/Jakarta": 7,
    "Asia/Bangkok": 7,
    "America/Argentina/Buenos_Aires": -3,
    "Europe/Madrid": 2,                  # CEST
    "Europe/Rome": 2,                    # CEST
    "Europe/Amsterdam": 2,               # CEST
}

# Weighted activity pools (popular activities have higher selection weight)
ACTIVITIES = {
    "web_browsing": 5, "email_access": 4, "file_download": 3,
    "github_access": 2, "college_portal": 3, "vpn_admin_panel": 1,
    "bulk_data_transfer": 1, "dns_heavy_session": 1, "login_attempt": 3,
    "cloud_upload": 1, "code_commit": 2, "slack_teams": 4,
    "database_query": 1, "ssh_session": 2, "admin_action": 1,
    "config_change": 1, "share_link": 2,
}
ACTIVITY_LIST = list(ACTIVITIES.keys())
ACTIVITY_WEIGHTS = list(ACTIVITIES.values())

DEVICE_TYPES = ["desktop", "laptop", "mobile", "tablet"]
OS_BY_DEVICE = {
    "desktop": ["Windows 11", "Windows 10", "macOS 14", "Ubuntu 22.04"],
    "laptop":  ["Windows 11", "macOS 14", "Ubuntu 22.04", "ChromeOS"],
    "mobile":  ["Android 14", "Android 15", "iOS 18"],
    "tablet":  ["iPadOS 18", "Android 14", "Windows 11"],
}
BROWSERS = ["Chrome 125", "Firefox 127", "Edge 125", "Safari 18", "Brave 1.68"]

# Known cloud storage domains for data_to_personal_cloud anomaly
CLOUD_DOMAINS = [
    "drive.google.com", "dropbox.com", "onedrive.live.com",
    "icloud.com", "box.com", "mega.io",
]

# High-risk countries for known_bad_region
RISK_COUNTRIES = ["KP", "IR", "RU", "SY", "CU"]


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * r * atan2(sqrt(a), sqrt(1 - a))


def make_device_fingerprint(os_name, browser, device_type):
    raw = f"{device_type}-{os_name.replace(' ', '').lower()}-{browser.split()[0].lower()}"
    return f"{raw}-{uuid.uuid4().hex[:6]}"


def local_hour(ts_iso, tz_name):
    offset = TZ_OFFSET.get(tz_name, 0)
    ts = datetime.fromisoformat(ts_iso)
    return (ts + timedelta(hours=offset)).hour


class DeterministicUUID:
    """Seedable UUID4 for reproducibility."""
    def __init__(self, seed):
        self._rng = random.Random(seed)

    def uuid4(self):
        return uuid.UUID(bytes=bytes(self._rng.getrandbits(8) for _ in range(16)), version=4)


class IPAllocator:
    """Ensures every IP maps to exactly one city."""

    def __init__(self):
        self._ip_to_city = {}
        self._next_octet = 1

    def allocate(self, city_name):
        for ip, cid in self._ip_to_city.items():
            if cid == city_name:
                return ip
        ip = f"10.{self._next_octet // 254}.{self._next_octet % 254}.{random.randint(1, 254)}"
        self._next_octet += 1
        self._ip_to_city[ip] = city_name
        return ip

    def allocate_fake(self, city_name):
        """Allocate a 'new/unknown' IP for a given city (used by anomalies)."""
        ip = f"172.16.{random.randint(0, 254)}.{random.randint(1, 254)}"
        while ip in self._ip_to_city:
            ip = f"172.16.{random.randint(0, 254)}.{random.randint(1, 254)}"
        self._ip_to_city[ip] = city_name
        return ip


class UserProfile:
    def __init__(self, user_id, ip_allocator, activity_rng, device_rng):
        self.user_id = user_id
        self.home_city, self.home_country, self.lat, self.lon = random.choice(CITIES)
        self.home_tz = CITY_TZ[self.home_city]
        self.device_type = device_rng.choice(DEVICE_TYPES)
        self.home_os = device_rng.choice(OS_BY_DEVICE[self.device_type])
        self.home_browser = random.choice(BROWSERS)
        self.home_device = make_device_fingerprint(self.home_os, self.home_browser, self.device_type)
        self.home_ip = ip_allocator.allocate(self.home_city)
        self.role = random.choice(["student", "faculty", "admin", "researcher", "contractor"])

        # Working hours (user-local time)
        self.typical_hour_start = random.choice([7, 8, 9, 10])
        self.typical_hour_end = random.choice([17, 18, 19, 20, 21, 22])

        self.typical_activities = activity_rng.sample(ACTIVITY_LIST, k=random.randint(3, 6))

        # Activity weight (some users more active than others)
        self.activity_weight = random.choices([1, 2, 3, 4, 5], weights=[10, 25, 35, 20, 10])[0]

    def normal_hour(self):
        return random.randint(self.typical_hour_start, self.typical_hour_end)


def pick_weighted_activity():
    return random.choices(ACTIVITY_LIST, weights=ACTIVITY_WEIGHTS, k=1)[0]


def build_event(profile, timestamp, anomaly_type=None, uuid_gen=None, **overrides):
    uid = uuid_gen.uuid4() if uuid_gen else uuid.uuid4()
    ts = timestamp.isoformat()
    ev = {
        "event_id": str(uid),
        "user_id": profile.user_id,
        "timestamp": ts,
        "device_type": profile.device_type,
        "device_fingerprint": profile.home_device,
        "os": profile.home_os,
        "browser": profile.home_browser,
        "ip": profile.home_ip,
        "geo_city": profile.home_city,
        "geo_country": profile.home_country,
        "lat": profile.lat,
        "lon": profile.lon,
        "role": profile.role,
        "vpn_detected": False,
        "login_success": True,
        "data_size_mb": None,
        "cloud_domain": None,
        "activity": pick_weighted_activity(),
        "session_id": str(uuid.uuid4()),
        "is_anomalous_ground_truth": anomaly_type is not None,
        "anomaly_type": anomaly_type,
        "implied_speed_kmh": None,
        "user_home_tz": profile.home_tz,
        "user_local_hour": local_hour(ts, profile.home_tz),
        "event_city_tz": CITY_TZ.get(overrides.get("geo_city", profile.home_city), profile.home_tz),
    }
    ev.update(overrides)
    return ev


def generate_normal_event(profile, base_date, ip_allocator, uuid_gen):
    hour = profile.normal_hour()
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = base_date.replace(hour=hour, minute=minute, second=second)

    data_size = None
    activity = pick_weighted_activity()
    if activity in ("bulk_data_transfer", "file_download", "cloud_upload"):
        data_size = round(random.uniform(0.5, 50), 2)

    ev = build_event(profile, ts, uuid_gen=uuid_gen,
                     activity=activity, data_size_mb=data_size)

    # 5% chance of legitimate VPN usage
    if random.random() < 0.05:
        ev["vpn_detected"] = True
        ev["ip"] = ip_allocator.allocate_fake(profile.home_city)

    # 2% chance of normal login failure (typo, forgot password)
    if random.random() < 0.02:
        ev["login_success"] = False
        ev["activity"] = "login_attempt"

    return ev


def _local_to_utc(base_date, local_hour_val, tz_name):
    """Convert a local hour on base_date to a UTC datetime (handles fractional TZ offsets)."""
    offset = TZ_OFFSET.get(tz_name, 0)
    local_minute = random.randint(0, 59)
    local_second = random.randint(0, 59)
    local_dt = base_date.replace(hour=local_hour_val, minute=local_minute, second=local_second)
    offset_hours = int(offset)
    offset_minutes = int(abs(offset - offset_hours) * 60)
    if offset >= 0:
        return local_dt - timedelta(hours=offset_hours, minutes=offset_minutes)
    else:
        return local_dt - timedelta(hours=offset_hours) + timedelta(minutes=offset_minutes)


def generate_off_hours(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: login during 1-5 AM user-local time (same city, no VPN change)."""
    local_odd = random.choice([1, 2, 3, 4, 5])
    ts = _local_to_utc(base_date, local_odd, profile.home_tz)
    return build_event(profile, ts, "off_hours_access", uuid_gen=uuid_gen,
                       ip=ip_allocator.allocate_fake(profile.home_city))


def generate_dormant_reactivation(profile, _base_date, prev_city, _ip_allocator, uuid_gen):
    """Anomaly: account inactive >90 days suddenly active."""
    if prev_city is None:
        return None
    last_ts = prev_city[4]  # (city, country, lat, lon, timestamp)
    last_dt = datetime.fromisoformat(last_ts)
    new_ts = last_dt + timedelta(days=random.randint(91, 180))
    hour = profile.normal_hour()
    new_ts = new_ts.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    return build_event(profile, new_ts, "dormant_account_reactivation", uuid_gen=uuid_gen)


def generate_data_to_cloud(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: large upload to personal cloud storage."""
    ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
    cloud_domain = random.choice(CLOUD_DOMAINS)
    return build_event(profile, ts, "data_to_personal_cloud", uuid_gen=uuid_gen,
                       activity="cloud_upload",
                       data_size_mb=round(random.uniform(100, 2000), 1),
                       cloud_domain=cloud_domain,
                       ip=ip_allocator.allocate_fake(profile.home_city))


def generate_cookie_reuse(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: same device fingerprint, different IP, same session, minutes apart.
    Generates TWO events sharing a session_id."""
    hour = profile.normal_hour()
    base_ts = base_date.replace(hour=hour, minute=random.randint(0, 30), second=random.randint(0, 59))
    session = str(uuid.uuid4())

    first_ip = ip_allocator.allocate_fake(profile.home_city)
    second_ip = ip_allocator.allocate_fake(profile.home_city)

    ev1 = build_event(profile, base_ts, "cookie_reuse", uuid_gen=uuid_gen,
                      ip=first_ip, session_id=session)
    ev2_ts = base_ts + timedelta(minutes=random.randint(2, 15))
    ev2 = build_event(profile, ev2_ts, "cookie_reuse", uuid_gen=uuid_gen,
                      ip=second_ip, session_id=session)
    return [ev1, ev2]


def generate_frequency_burst(profile, base_date, _prev_city, _ip_allocator, uuid_gen):
    """Anomaly: 5-10 events from same user in under 3 minutes."""
    hour = profile.normal_hour()
    start_ts = base_date.replace(hour=hour, minute=random.randint(0, 57), second=0)
    burst_count = random.randint(5, 10)
    events = []
    for i in range(burst_count):
        ts = start_ts + timedelta(seconds=random.randint(0, 180))
        ev = build_event(profile, ts, "unusual_login_frequency", uuid_gen=uuid_gen,
                         login_success=random.choices([True, False], weights=[7, 3])[0])
        events.append(ev)
    return events


def generate_new_country_odd_hour(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: login from a new country during user's sleeping hours (user-local)."""
    candidates = [c for c in CITIES if c[1] != profile.home_country]
    city, country, lat, lon = random.choice(candidates)
    local_sleep = random.choice([1, 2, 3, 4])
    ts = _local_to_utc(base_date, local_sleep, profile.home_tz)
    return build_event(profile, ts, "new_country_odd_hour", uuid_gen=uuid_gen,
                       geo_city=city, geo_country=country, lat=lat, lon=lon,
                       ip=ip_allocator.allocate(city),
                       vpn_detected=random.choice([True, False]))


def generate_unknown_device_vpn(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: first-seen device connecting via VPN."""
    os_name = random.choice(OS_BY_DEVICE[random.choice(DEVICE_TYPES)])
    browser = random.choice(BROWSERS)
    device_type = random.choice(DEVICE_TYPES)
    fingerprint = make_device_fingerprint(os_name, browser, device_type)
    ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
    return build_event(profile, ts, "unknown_device_vpn", uuid_gen=uuid_gen,
                       device_type=device_type, device_fingerprint=fingerprint,
                       os=os_name, browser=browser, vpn_detected=True,
                       ip=ip_allocator.allocate_fake(profile.home_city))


def generate_impossible_travel(profile, _base_date, prev_city_info, ip_allocator, uuid_gen):
    """Anomaly: user appears in two far-apart locations too quickly."""
    if prev_city_info is None:
        return None
    prev_city, prev_country, prev_lat, prev_lon, prev_ts = prev_city_info
    candidates = [c for c in CITIES if c[1] != prev_country]
    if not candidates:
        return None
    city, country, lat, lon = random.choice(candidates)
    prev_dt = datetime.fromisoformat(prev_ts)
    gap_minutes = random.randint(15, 120)
    new_ts = prev_dt + timedelta(minutes=gap_minutes)
    dist = haversine_km(prev_lat, prev_lon, lat, lon)
    hours = gap_minutes / 60.0
    speed = round(dist / hours, 1) if hours > 0 else None
    return build_event(profile, new_ts, "impossible_travel", uuid_gen=uuid_gen,
                       geo_city=city, geo_country=country, lat=lat, lon=lon,
                       ip=ip_allocator.allocate(city), implied_speed_kmh=speed)


def generate_bulk_transfer_new_ip(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: large data transfer to/from a previously unseen IP."""
    ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
    return build_event(profile, ts, "bulk_transfer_new_ip", uuid_gen=uuid_gen,
                       activity="bulk_data_transfer",
                       data_size_mb=round(random.uniform(500, 5000), 1),
                       ip=ip_allocator.allocate_fake(profile.home_city))


def generate_brute_force(profile, base_date, _prev_city, ip_allocator, uuid_gen):
    """Anomaly: multiple rapid login failures."""
    ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
    return build_event(profile, ts, "brute_force_pattern", uuid_gen=uuid_gen,
                       login_success=False, activity="login_attempt",
                       ip=ip_allocator.allocate_fake(profile.home_city))


ANOMALY_GENERATORS = {
    "new_country_odd_hour": generate_new_country_odd_hour,
    "unknown_device_vpn": generate_unknown_device_vpn,
    "impossible_travel": generate_impossible_travel,
    "bulk_transfer_new_ip": generate_bulk_transfer_new_ip,
    "brute_force_pattern": generate_brute_force,
    "off_hours_access": generate_off_hours,
    "dormant_account_reactivation": generate_dormant_reactivation,
    "data_to_personal_cloud": generate_data_to_cloud,
    "cookie_reuse": generate_cookie_reuse,
    "unusual_login_frequency": generate_frequency_burst,
}
ANOMALY_TYPES = list(ANOMALY_GENERATORS.keys())


def generate_dataset(num_users, num_events, anomaly_ratio, seed):
    rng = random.Random(seed)
    random.seed(seed)
    uuid_gen = DeterministicUUID(seed + 999)

    ip_allocator = IPAllocator()

    # -- Create users with power-law-ish activity distribution --
    profiles = []
    for i in range(num_users):
        p = UserProfile(f"u_{i:03d}", ip_allocator, activity_rng=rng, device_rng=rng)
        profiles.append(p)

    # Weighted user selection (some users 5x more active)
    user_weights = [p.activity_weight for p in profiles]

    base_date = datetime(2026, 6, 2)

    events = []
    last_city_by_user = {}

    anomaly_type_quota = {t: 0 for t in ANOMALY_TYPES}
    current_anomalous = 0
    target_anomalous = int(num_events * anomaly_ratio)

    while len(events) < num_events:
        profile = rng.choices(profiles, weights=user_weights, k=1)[0]
        day_offset = rng.randint(0, 29)
        this_base = base_date + timedelta(days=day_offset)

        prev_city = last_city_by_user.get(profile.user_id)

        # Dynamic probability to hit target event-level anomaly ratio
        remaining = num_events - len(events)
        needed = target_anomalous - current_anomalous
        prob = max(0.0, needed / max(remaining, 1))
        should_generate_anomaly = rng.random() < prob

        if not should_generate_anomaly:
            ev = generate_normal_event(profile, this_base, ip_allocator, uuid_gen)
            events.append(ev)

        else:
            counts = list(anomaly_type_quota.values())
            min_count = min(counts)
            candidates = [t for t, c in anomaly_type_quota.items() if c == min_count]
            chosen = rng.choice(candidates)
            anomaly_type_quota[chosen] += 1

            gen_fn = ANOMALY_GENERATORS[chosen]
            result = gen_fn(profile, this_base, prev_city, ip_allocator, uuid_gen)

            if result is None:
                ev = generate_normal_event(profile, this_base, ip_allocator, uuid_gen)
                events.append(ev)
                current_anomalous += 1 if ev["is_anomalous_ground_truth"] else 0
            elif isinstance(result, list):
                for ev in result:
                    if len(events) < num_events:
                        events.append(ev)
                        current_anomalous += 1 if ev["is_anomalous_ground_truth"] else 0
            else:
                events.append(result)
                current_anomalous += 1 if result["is_anomalous_ground_truth"] else 0

        last_ev = events[-1]
        last_city_by_user[profile.user_id] = (
            last_ev["geo_city"], last_ev["geo_country"],
            last_ev["lat"], last_ev["lon"], last_ev["timestamp"]
        )
    events.sort(key=lambda e: e["timestamp"])
    return events


def write_outputs(events, out_dir):
    json_path = os.path.join(out_dir, "synthetic_identity_events.json")
    csv_path = os.path.join(out_dir, "synthetic_identity_events.csv")

    with open(json_path, "w") as f:
        json.dump(events, f, indent=2)

    fieldnames = list(events[0].keys())
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow(e)

    return json_path, csv_path


def verify(events):
    from collections import defaultdict, Counter

    errors = []
    warnings = []

    # 1. IP-geo consistency
    ip_geo = defaultdict(set)
    for e in events:
        ip_geo[e["ip"]].add(e["geo_city"])
    multi = [ip for ip, cities in ip_geo.items() if len(cities) > 1]
    if multi:
        errors.append(f"{len(multi)} IPs map to multiple cities: {multi[:5]}")

    # 2. Speed sanity
    speed_events = [e for e in events if e["implied_speed_kmh"] is not None]
    for e in speed_events:
        if e["anomaly_type"] != "impossible_travel":
            errors.append(f"Speed without impossible_travel: {e['event_id'][:8]}")
    speeds = [e["implied_speed_kmh"] for e in speed_events if e["implied_speed_kmh"] is not None]
    if speeds:
        print(f"  Speed range: {min(speeds):.0f} – {max(speeds):.0f} km/h")
        print(f"  Travel events: {len(speeds)}")

    # 3. VPN: both normal and anomalous
    vpn_anom = sum(1 for e in events if e["vpn_detected"] and e["is_anomalous_ground_truth"])
    vpn_norm = sum(1 for e in events if e["vpn_detected"] and not e["is_anomalous_ground_truth"])
    if vpn_anom > 0 and vpn_norm == 0:
        errors.append("All VPN events are anomalous (no legitimate VPN)")

    # 4. Login failures: both normal and anomalous
    fail_anom = sum(1 for e in events if not e["login_success"] and e["is_anomalous_ground_truth"])
    fail_norm = sum(1 for e in events if not e["login_success"] and not e["is_anomalous_ground_truth"])
    if fail_anom > 0 and fail_norm == 0:
        errors.append("All login failures are anomalous (no typos)")

    # 5. Anomaly type distribution
    anom_types = Counter(e["anomaly_type"] for e in events if e["is_anomalous_ground_truth"])
    expected_per_type = sum(anom_types.values()) / max(len(anom_types), 1)

    # 6. Off-hours check: user_local_hour should be 1-5 for off_hours_access
    off_hours = [e for e in events if e["anomaly_type"] == "off_hours_access"]
    for e in off_hours:
        lh = e["user_local_hour"]
        if lh not in range(1, 6):
            warnings.append(f"off_hours_access user_local_hour={lh} (expected 1-5): {e['event_id'][:8]}")

    # 7. Dormant reactivation: should have timestamps far apart
    dormant = [e for e in events if e["anomaly_type"] == "dormant_account_reactivation"]
    if dormant:
        print(f"  Dormant reactivations: {len(dormant)}")

    # 8. Cookie reuse: should have pairs sharing session_id
    cookie = [e for e in events if e["anomaly_type"] == "cookie_reuse"]
    sessions = Counter(e["session_id"] for e in cookie)
    singles = [s for s, c in sessions.items() if c < 2]
    if singles:
        warnings.append(f"cookie_reuse: {len(singles)} sessions have only 1 event (expected pairs)")

    # 9. Frequency burst: should have clusters of events
    freq = [e for e in events if e["anomaly_type"] == "unusual_login_frequency"]
    print(f"  Frequency burst events: {len(freq)}")

    # 10. Cloud anomaly: should have cloud_domain and large data_size
    cloud = [e for e in events if e["anomaly_type"] == "data_to_personal_cloud"]
    for e in cloud:
        if not e["cloud_domain"]:
            errors.append(f"data_to_personal_cloud missing cloud_domain: {e['event_id'][:8]}")
        if e.get("data_size_mb", 0) < 50:
            warnings.append(f"data_to_personal_cloud small data_size: {e['data_size_mb']}MB")

    # 11. Country distribution (warning only)
    countries = Counter(e["geo_country"] for e in events)
    max_country_pct = max(countries.values()) / len(events) * 100
    if max_country_pct > 25:
        warnings.append(f"Country skew: {countries.most_common(1)[0][0]} has {max_country_pct:.0f}% of events")

    # 12. User distribution (warning if too uniform)
    users = Counter(e["user_id"] for e in events)
    user_counts = list(users.values())
    if max(user_counts) / min(user_counts) < 1.5:
        warnings.append("User distribution too uniform (all users within 1.5x of each other)")

    total = len(events)
    anom = sum(1 for e in events if e["is_anomalous_ground_truth"])
    print(f"  Total: {total}, Anomalous: {anom} ({anom/total*100:.1f}%)")
    print(f"  VPN: {vpn_norm} normal, {vpn_anom} anomalous")
    print(f"  Login failures: {fail_norm} normal, {fail_anom} anomalous")

    print(f"\n  Anomaly type distribution:")
    for t, c in sorted(anom_types.items()):
        bar = "█" * max(1, int(c / max(anom_types.values()) * 30))
        print(f"    {t:35s} {c:4d} {bar}")

    if errors:
        print(f"\n  ❌ {len(errors)} error(s):")
        for err in errors:
            print(f"     - {err}")
    else:
        print("  ✅ All checks passed")

    if warnings:
        print(f"\n  ⚠ {len(warnings)} warning(s):")
        for w in warnings[:10]:
            print(f"     - {w}")
        if len(warnings) > 10:
            print(f"     ... and {len(warnings)-10} more")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic identity/device telemetry (v2).")
    parser.add_argument("--users", type=int, default=20, help="Number of distinct user profiles")
    parser.add_argument("--events", type=int, default=20000, help="Total number of events to generate")
    parser.add_argument("--anomaly-ratio", type=float, default=0.08, help="Fraction of events that are anomalous")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--out-dir", type=str, default=".", help="Output directory")
    parser.add_argument("--verify", action="store_true", help="Run self-verification after generation")
    args = parser.parse_args()

    events = generate_dataset(args.users, args.events, args.anomaly_ratio, args.seed)
    json_path, csv_path = write_outputs(events, args.out_dir)

    num_anomalous = sum(1 for e in events if e["is_anomalous_ground_truth"])
    print(f"Generated {len(events)} events ({num_anomalous} anomalous, {len(events)-num_anomalous} normal)")
    print(f"Users: {args.users} | Anomaly ratio: {args.anomaly_ratio}")
    print(f"Wrote: {json_path}")
    print(f"Wrote: {csv_path}")

    if args.verify:
        print("\nSelf-verification:")
        verify(events)


if __name__ == "__main__":
    main()
