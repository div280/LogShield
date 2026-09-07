"""
attack_map.py
Simulated Global Attack Map visual component for LogShield dashboard.
Generates in-memory cyberthreat attack trajectories and glowing markers
converging on the forensic subject machine in India.

Strictly visual and in-memory: does not read, write, or modify any dataset,
model files, or forensic pipeline outputs.
"""
import math
import random
import plotly.graph_objects as go


# Global coordinate pool for simulated attacker origins
SIMULATED_ATTACK_ORIGINS = [
    {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874, "vector": "Remote Exploit Attempt"},
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "vector": "Credential Spraying Sequence"},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278, "vector": "Suspicious PowerShell Ingress"},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "vector": "Anomalous Port Sweep"},
    {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "vector": "Brute Force Authentication"},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "vector": "Privilege Escalation Probe"},
    {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "vector": "Unauthorized Token Probe"},
    {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "vector": "Lateral Movement Simulation"},
    {"country": "Canada", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "vector": "Automated Vulnerability Scan"},
    {"country": "South Korea", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "vector": "Malicious DLL Injection Probe"},
    {"country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "vector": "Security Descriptor Tamper Attempt"},
    {"country": "Sweden", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686, "vector": "Event Log Clearing Probe"},
    {"country": "South Africa", "city": "Johannesburg", "lat": -26.2041, "lon": 28.0473, "vector": "Kerberoasting Probe"},
    {"country": "United Arab Emirates", "city": "Dubai", "lat": 25.2048, "lon": 55.2708, "vector": "Pass-the-Hash Simulation"},
    {"country": "Poland", "city": "Warsaw", "lat": 52.2297, "lon": 21.0122, "vector": "Anomalous Service Creation"},
    {"country": "Romania", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025, "vector": "Reconnaissance Fingerprinting"},
    {"country": "Vietnam", "city": "Hanoi", "lat": 21.0285, "lon": 105.8542, "vector": "Scheduled Task Modification"},
    {"country": "Mexico", "city": "Mexico City", "lat": 19.4326, "lon": -99.1332, "vector": "SMB Session Hijacking Probe"},
    {"country": "Argentina", "city": "Buenos Aires", "lat": -34.6037, "lon": -58.3816, "vector": "WMI Persistence Ingress"},
    {"country": "Ireland", "city": "Dublin", "lat": 53.3498, "lon": -6.2603, "vector": "Process Hollow Simulation"}
]


def generate_flight_arc(
        start_lon: float,
        start_lat: float,
        end_lon: float,
        end_lat: float,
        num_steps: int = 30,
        arc_height: float = 12.0) -> tuple[list[float], list[float]]:
    """
    Computes curved bezier arc coordinates between an attacker source
    and a victim destination on a world map.

    Parameters:
    start_lon (float): Longitude of the attacker source.
    start_lat (float): Latitude of the attacker source.
    end_lon (float): Longitude of the victim destination.
    end_lat (float): Latitude of the victim destination.
    num_steps (int): Number of interpolation points along the arc.
    arc_height (float): Peak vertical curvature height in degrees.

    Returns:
    tuple[list[float], list[float]]: Pair of (longitudes, latitudes) lists.

    Time complexity: O(n) where n is num_steps.
    Space complexity: O(n) for the output coordinate lists.
    """
    lons = []
    lats = []

    # Handle 180 degree longitude wrap-around for shortest arc path
    d_lon = end_lon - start_lon
    if d_lon > 180:
        d_lon -= 360
    elif d_lon < -180:
        d_lon += 360

    for i in range(num_steps + 1):
        t = i / float(num_steps)
        # Linear interpolation for longitude
        lon = start_lon + (t * d_lon)
        if lon > 180:
            lon -= 360
        elif lon < -180:
            lon += 360

        # Parabolic arch offset for latitude
        base_lat = start_lat + (t * (end_lat - start_lat))
        # Parabolic bulge peak at t = 0.5
        height_offset = arc_height * math.sin(math.pi * t)
        lat = base_lat + height_offset

        # Clamp latitude to valid world boundaries
        lat = max(-85.0, min(85.0, lat))

        lons.append(lon)
        lats.append(lat)

    return lons, lats


def create_simulated_attack_map(
        victim_lat: float | None = None,
        victim_lon: float | None = None,
        computer_name: str = "FORENSIC-HOST",
        city: str = "Bangalore",
        country: str = "India",
        anomaly_count: int = 0,
        BG: str = "#0A0C10",
        SURFACE: str = "#0F1319",
        BORDER: str = "#1E2530",
        ACCENT: str = "#E8343A",
        SUCCESS: str = "#00C853",
        WARN: str = "#FFB300",
        CYAN: str = "#00D4FF",
        TXT1: str = "#F0F2F5",
        TXT2: str = "#6B7280") -> go.Figure:
    """
    Creates a simulated global cyberthreat map where curved attack lines
    fly in from various countries and land on the victim machine in India.

    Parameters:
    victim_lat (float | None): Subject machine latitude (defaults to Bangalore if None).
    victim_lon (float | None): Subject machine longitude (defaults to Bangalore if None).
    computer_name (str): Hostname of the analyzed machine.
    city (str): Subject machine city name.
    country (str): Subject machine country name.
    anomaly_count (int): Accepted for API compatibility. Not used. Attacker count is a fixed random value between 5 and 15, decoupled from all session data.
    BG (str): Dashboard background color token.
    SURFACE (str): Card surface color token.
    BORDER (str): Border color token.
    ACCENT (str): Threat/alarm accent color hex.
    SUCCESS (str): Normal/success color hex.
    WARN (str): Warning color hex.
    CYAN (str): Highlight cyan color hex.
    TXT1 (str): Primary text color hex.
    TXT2 (str): Secondary text color hex.

    Returns:
    go.Figure: Plotly Scattergeo figure representing the simulated cyberthreat map.

    Time complexity: O(k * s) where k is number of simulated attackers and s is arc interpolation steps.
    Space complexity: O(k * s) for the Plotly trace structures and points.
    """
    # Fallback to Bangalore, India if coordinates are not supplied
    if victim_lat is None or not math.isfinite(victim_lat):
        victim_lat = 12.9716
    if victim_lon is None or not math.isfinite(victim_lon):
        victim_lon = 77.5946

    # Determine theme mode and color tokens
    is_dark = (BG.upper() in ["#0A0C10", "#0F1319", "#080A0E"]) or ("#0" in BG)
    primary_txt = TXT1 if is_dark else ("#0F172A" if TXT1 in ["#F0F2F5", "#FFFFFF"] else TXT1)
    secondary_txt = TXT2 if is_dark else ("#475569" if TXT2 in ["#6B7280", "#94A3B8"] else TXT2)
    arc_opacity = 0.65 if is_dark else 0.85
    ring_levels = [(42, 0.08), (28, 0.18), (18, 0.45)] if is_dark else [(42, 0.18), (28, 0.35), (18, 0.70)]

    # Attacker count is a fixed random value between 5 and 15.
    # It is completely decoupled from any session data, uploaded file,
    # or forensic pipeline result. Seeded from current time so it
    # varies naturally on each page load without using real data.
    import time as _time
    _seed = int(_time.time()) // 30  # changes every 30 seconds
    rng = random.Random(_seed)
    num_attackers = rng.randint(5, 15)

    # Select distinct attacker origins from pool
    rng2 = random.Random(_seed + 1)
    selected_attackers = rng2.sample(
        SIMULATED_ATTACK_ORIGINS,
        k=min(num_attackers, len(SIMULATED_ATTACK_ORIGINS))
    )

    fig = go.Figure()

    # 1. Draw curved flight lines from each attacker origin to the victim location
    for idx, att in enumerate(selected_attackers):
        # Vary arc height slightly for visually layered 3D cyber-arc feel
        arc_height = 8.0 + (idx % 3) * 6.0
        if att["lat"] > victim_lat:
            arc_height = -arc_height if abs(att["lat"] - victim_lat) > 40 else arc_height

        arc_lons, arc_lats = generate_flight_arc(
            start_lon=att["lon"],
            start_lat=att["lat"],
            end_lon=victim_lon,
            end_lat=victim_lat,
            num_steps=32,
            arc_height=arc_height
        )

        # Line color styling: threat gradient feel
        line_color = ACCENT if (idx % 2 == 0) else WARN
        line_width = 1.8 if (idx % 2 == 0) else 1.4

        fig.add_trace(go.Scattergeo(
            lon=arc_lons,
            lat=arc_lats,
            mode="lines",
            line=dict(
                width=line_width,
                color=line_color
            ),
            opacity=arc_opacity,
            hoverinfo="none",
            showlegend=False
        ))

    # 2. Draw simulated attacker origin markers
    att_lons = [a["lon"] for a in selected_attackers]
    att_lats = [a["lat"] for a in selected_attackers]
    att_hover = [
        f"Simulated Origin: {a['city']}, {a['country']}<br>"
        f"Vector: {a['vector']}<br>"
        f"Target: {computer_name} ({city}, {country})<br>"
        f"Classification: Ingress Vector (Simulation)"
        for a in selected_attackers
    ]

    fig.add_trace(go.Scattergeo(
        lon=att_lons,
        lat=att_lats,
        mode="markers",
        marker=dict(
            size=7,
            color=WARN,
            opacity=0.85,
            symbol="circle",
            line=dict(width=1, color="#FFFFFF")
        ),
        text=att_hover,
        hoverinfo="text",
        name="Simulated Ingress Source",
        showlegend=True
    ))

    # 3. Draw pulsing/glowing victim location markers
    for ring_size, ring_opacity in ring_levels:
        fig.add_trace(go.Scattergeo(
            lon=[victim_lon],
            lat=[victim_lat],
            mode="markers",
            marker=dict(
                size=ring_size,
                color=ACCENT,
                opacity=ring_opacity,
                line=dict(width=0)
            ),
            hoverinfo="none",
            showlegend=False
        ))

    # Central victim focal point
    victim_hover = (
        f"Victim Host: {computer_name}<br>"
        f"Location: {city}, {country}<br>"
        f"Role: Forensic Investigation Target<br>"
        f"Active Ingress Streams: {len(selected_attackers)} Simulated Vectors"
    )

    fig.add_trace(go.Scattergeo(
        lon=[victim_lon],
        lat=[victim_lat],
        mode="markers+text",
        text=[f"  {computer_name} (Victim Target)"],
        textposition="top right",
        textfont=dict(
            size=12,
            color=primary_txt,
            family="Inter"
        ),
        marker=dict(
            size=16,
            color=ACCENT,
            symbol="circle",
            line=dict(
                width=2.5,
                color="#FFFFFF"
            )
        ),
        hovertext=victim_hover,
        hoverinfo="text",
        name="Victim Host (India)",
        showlegend=True
    ))

    # Map visual styling matching LogShield dark/light theme
    land_color = "#161D2B" if is_dark else "#D6DEE8"
    ocean_color = "#0A0D14" if is_dark else "#C9D6E3"
    country_border = (BORDER if BORDER else "#2A3649") if is_dark else "#7A8FAD"

    fig.update_layout(
        geo=dict(
            bgcolor="rgba(0,0,0,0)",
            landcolor=land_color,
            oceancolor=ocean_color,
            showocean=True,
            showland=True,
            showcountries=True,
            countrycolor=country_border,
            countrywidth=0.8,
            showframe=False,
            showcoastlines=True,
            coastlinecolor=country_border,
            coastlinewidth=0.8,
            projection_type="natural earth",
            center=dict(lat=24.0, lon=50.0),
            projection_scale=1.15
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Inter",
            color=secondary_txt,
            size=11
        ),
        title=dict(
            text="Simulated Global Cyberthreat Ingress Map",
            font=dict(
                size=13,
                color=primary_txt,
                family="Inter"
            )
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            bordercolor=BORDER if is_dark else "#CBD5E1",
            borderwidth=1,
            font=dict(size=11, color=secondary_txt),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        margin=dict(l=0, r=0, t=50, b=0),
        height=420
    )

    return fig
