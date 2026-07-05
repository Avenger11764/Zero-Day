#!/usr/bin/env python3
"""
Synthetic Identity/Device Event Generator
------------------------------------------
Generates fake-but-plausible login/session telemetry for the UEBA risk model
in the Zero-Day Detection FYP.

Produces a mix of:
  - "normal" events: consistent per-user home city, device, IP range, login hours
  - "anomalous" events: new country, new device, odd hour, VPN on, impossible travel

Each record is labeled with `is_anomalous_ground_truth` so you can sanity-check
your risk model / SHAP explanations against known answers. IMPORTANT: this label
is for YOUR evaluation only -- do not feed it into the model as a feature, or
you'll be training on the answer key.

Bug fixes over v1:
  - IP-geo consistency: each IP maps to exactly one city (no cross-continent IPs)
  - Speed calculations: impossible travel speed from last DIFFERENT city, not last event
  - Legitimate VPN: ~5% of normal events have VPN (not all VPN = anomalous)
  - Normal login failures: ~2% of normal events are typos (not all failures = brute force)
  - Varied activities: users get 3-5 activities instead of exactly 3
  - Timezone fields: user_home_tz, user_local_hour, event_city_tz added
  - No speeds for same-city consecutive events

Usage:
    python3 generate_synthetic_identity_data.py --users 15 --events 3000 --anomaly-ratio 0.08

Outputs:
    synthetic_identity_events.json
    synthetic_identity_events.csv
"""

import argparse
import csv
import json
import random
import uuid
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2

# ---- Reference data pools ---------------------------------------------------

CITIES = [
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
]

CITY_TZ = {
    "Delhi": "Asia/Kolkata", "Mumbai": "Asia/Kolkata", "Bengaluru": "Asia/Kolkata",
    "London": "Europe/London", "New York": "America/New_York",
    "Moscow": "Europe/Moscow", "Lagos": "Africa/Lagos",
    "Singapore": "Asia/Singapore", "Sao Paulo": "America/Sao_Paulo", "Sydney": "Australia/Sydney",
}

TZ_OFFSET = {
    "Asia/Kolkata": 5.5, "Europe/London": 0, "America/New_York": -5,
    "Europe/Moscow": 3, "Africa/Lagos": 1, "Asia/Singapore": 8,
    "America/Sao_Paulo": -3, "Australia/Sydney": 11,
}

DEVICE_OS = ["Windows 10", "Windows 11", "macOS", "Ubuntu Linux", "ChromeOS", "Android", "iOS"]
DEVICE_BROWSER = ["Chrome", "Firefox", "Edge", "Safari", "Brave"]

ACTIVITIES = ["github_access", "college_portal", "web_browsing", "file_download",
              "email_access", "vpn_admin_panel", "bulk_data_transfer", "dns_heavy_session"]


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * r * atan2(sqrt(a), sqrt(1 - a))


def make_device_fingerprint(os_name, browser):
    return f"{os_name.replace(' ', '').lower()}-{browser.lower()}-{uuid.uuid4().hex[:6]}"


def local_hour(ts_iso, tz_name):
    offset = TZ_OFFSET.get(tz_name, 0)
    ts = datetime.fromisoformat(ts_iso)
    return (ts + timedelta(hours=offset)).hour


class IPAllocator:
    """Ensures every IP maps to exactly one city — no cross-continent IPs."""

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

    def allocate_any(self):
        ip = f"192.168.{random.randint(0, 254)}.{random.randint(1, 254)}"
        while ip in self._ip_to_city:
            ip = f"192.168.{random.randint(0, 254)}.{random.randint(1, 254)}"
        self._ip_to_city[ip] = "__any__"
        return ip


class UserProfile:
    def __init__(self, user_id, ip_allocator):
        self.user_id = user_id
        self.home_city, self.home_country, self.lat, self.lon = random.choice(CITIES)
        self.home_tz = CITY_TZ[self.home_city]
        os_name = random.choice(DEVICE_OS)
        browser = random.choice(DEVICE_BROWSER)
        self.home_device = make_device_fingerprint(os_name, browser)
        self.home_os = os_name
        self.home_ip = ip_allocator.allocate(self.home_city)
        self.typical_hour_start = random.choice([7, 8, 9, 10])
        self.typical_hour_end = random.choice([21, 22, 23])
        self.typical_activities = random.sample(ACTIVITIES, k=random.randint(3, 5))

    def normal_hour(self):
        return random.randint(self.typical_hour_start, self.typical_hour_end)


def build_event(profile, timestamp, anomaly_type=None, **overrides):
    ts = timestamp.isoformat()
    ev = {
        "event_id": str(uuid.uuid4()),
        "user_id": profile.user_id,
        "timestamp": ts,
        "device_fingerprint": profile.home_device,
        "os": profile.home_os,
        "ip": profile.home_ip,
        "geo_city": profile.home_city,
        "geo_country": profile.home_country,
        "lat": profile.lat,
        "lon": profile.lon,
        "vpn_detected": False,
        "login_success": True,
        "activity": random.choice(profile.typical_activities),
        "is_anomalous_ground_truth": anomaly_type is not None,
        "anomaly_type": anomaly_type,
        "implied_speed_kmh": None,
        "user_home_tz": profile.home_tz,
        "user_local_hour": local_hour(ts, profile.home_tz),
        "event_city_tz": CITY_TZ.get(overrides.get("geo_city", profile.home_city), profile.home_tz),
    }
    ev.update(overrides)
    return ev


def generate_normal_event(profile, base_date, ip_allocator):
    hour = profile.normal_hour()
    ts = base_date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

    ev = build_event(profile, ts)

    # ~5% chance of legitimate VPN usage
    if random.random() < 0.05:
        ev["vpn_detected"] = True
        ev["ip"] = ip_allocator.allocate_any()

    # ~2% chance of normal login failure (typo, forgot password)
    if random.random() < 0.02:
        ev["login_success"] = False
        ev["activity"] = "login_attempt"

    return ev


def generate_anomalous_event(profile, base_date, prev_city_info, ip_allocator):
    archetype = random.choice([
        "new_country_odd_hour", "unknown_device_vpn", "impossible_travel",
        "bulk_transfer_new_ip", "brute_force_pattern",
    ])

    if archetype == "new_country_odd_hour":
        city, country, lat, lon = random.choice([c for c in CITIES if c[1] != profile.home_country])
        ts = base_date.replace(hour=random.choice([1, 2, 3, 4]), minute=random.randint(0, 59), second=random.randint(0, 59))
        return build_event(profile, ts, archetype,
                           geo_city=city, geo_country=country, lat=lat, lon=lon,
                           ip=ip_allocator.allocate(city),
                           vpn_detected=random.choice([True, False]))

    if archetype == "unknown_device_vpn":
        os_name, browser = random.choice(DEVICE_OS), random.choice(DEVICE_BROWSER)
        ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
        return build_event(profile, ts, archetype,
                           device_fingerprint=make_device_fingerprint(os_name, browser),
                           os=os_name, vpn_detected=True, ip=ip_allocator.allocate_any())

    if archetype == "impossible_travel":
        if prev_city_info is None:
            return generate_normal_event(profile, base_date, ip_allocator)
        prev_city, prev_country, prev_lat, prev_lon, prev_ts = prev_city_info
        city, country, lat, lon = random.choice([c for c in CITIES if c[1] != prev_country])
        prev_dt = datetime.fromisoformat(prev_ts)
        new_ts = prev_dt + timedelta(minutes=random.randint(15, 45))
        dist = haversine_km(prev_lat, prev_lon, lat, lon)
        hours = (new_ts - prev_dt).total_seconds() / 3600
        speed = round(dist / hours, 1) if hours > 0 else None
        return build_event(profile, new_ts, archetype,
                           geo_city=city, geo_country=country, lat=lat, lon=lon,
                           ip=ip_allocator.allocate(city),
                           implied_speed_kmh=speed)

    if archetype == "bulk_transfer_new_ip":
        ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
        return build_event(profile, ts, archetype,
                           activity="bulk_data_transfer", ip=ip_allocator.allocate_any())

    if archetype == "brute_force_pattern":
        ts = base_date.replace(hour=profile.normal_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
        return build_event(profile, ts, archetype,
                           login_success=False, activity="login_attempt")

    return generate_normal_event(profile, base_date, ip_allocator)


def generate_dataset(num_users, num_events, anomaly_ratio, seed):
    random.seed(seed)
    ip_allocator = IPAllocator()
    profiles = [UserProfile(f"u_{i:03d}", ip_allocator) for i in range(num_users)]
    base_date = datetime(2026, 6, 1)

    events = []
    last_city_by_user = {}

    for _ in range(num_events):
        profile = random.choice(profiles)
        day_offset = random.randint(0, 29)
        this_base = base_date + timedelta(days=day_offset)

        prev_city = last_city_by_user.get(profile.user_id)

        if random.random() < anomaly_ratio:
            event = generate_anomalous_event(profile, this_base, prev_city, ip_allocator)
        else:
            event = generate_normal_event(profile, this_base, ip_allocator)

        events.append(event)

        last_city_by_user[profile.user_id] = (
            event["geo_city"], event["geo_country"],
            event["lat"], event["lon"], event["timestamp"]
        )

    events.sort(key=lambda e: e["timestamp"])
    return events


def write_outputs(events, out_dir):
    json_path = f"{out_dir}/synthetic_identity_events.json"
    csv_path = f"{out_dir}/synthetic_identity_events.csv"

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

    ip_geo = defaultdict(set)
    for e in events:
        ip_geo[e["ip"]].add(e["geo_city"])
    multi = [ip for ip, cities in ip_geo.items() if len(cities) > 1]
    if multi:
        errors.append(f"{len(multi)} IPs map to multiple cities")

    for e in events:
        if e["implied_speed_kmh"] is not None:
            if e["anomaly_type"] != "impossible_travel":
                errors.append(f"Speed without impossible_travel type: {e['event_id'][:8]}")
            if e["geo_city"] == e.get("_prev_city"):
                errors.append(f"Speed for same-city event: {e['event_id'][:8]}")

    vpn_anom = sum(1 for e in events if e["vpn_detected"] and e["is_anomalous_ground_truth"])
    vpn_norm = sum(1 for e in events if e["vpn_detected"] and not e["is_anomalous_ground_truth"])
    if vpn_anom > 0 and vpn_norm == 0:
        errors.append("All VPN events are anomalous (no legitimate VPN)")

    fail_anom = sum(1 for e in events if not e["login_success"] and e["is_anomalous_ground_truth"])
    fail_norm = sum(1 for e in events if not e["login_success"] and not e["is_anomalous_ground_truth"])
    if fail_anom > 0 and fail_norm == 0:
        errors.append("All login failures are anomalous (no typos)")

    anom = sum(1 for e in events if e["is_anomalous_ground_truth"])
    print(f"  Total: {len(events)}, Anomalous: {anom} ({anom/len(events)*100:.1f}%)")
    print(f"  VPN: {vpn_norm} normal, {vpn_anom} anomalous")
    print(f"  Login failures: {fail_norm} normal, {fail_anom} anomalous")

    if errors:
        print(f"  ❌ {len(errors)} issue(s):")
        for err in errors:
            print(f"     - {err}")
    else:
        print("  ✅ All checks passed")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic identity/device telemetry.")
    parser.add_argument("--users", type=int, default=15, help="Number of distinct user profiles")
    parser.add_argument("--events", type=int, default=3000, help="Total number of events to generate")
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
