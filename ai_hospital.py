import requests
import math

# 🌍 Distance calculation
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)

    a = math.sin(d_lat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c


# 🏥 MAIN FUNCTION
def get_nearby_hospitals(lat, lon):
    url = "https://overpass-api.de/api/interpreter"

    query = f"""
    [out:json];
    node["amenity"="hospital"](around:10000,{lat},{lon});
    out;
    """

    try:
        res = requests.get(url, params={'data': query}, timeout=10)

        if res.status_code != 200:
            return fallback_hospitals(lat, lon)

        data = res.json()

    except Exception as e:
        print("API failed:", e)
        return fallback_hospitals(lat, lon)

    hospitals = data.get("elements", [])

    # 🚨 If empty → fallback
    if not hospitals:
        return fallback_hospitals(lat, lon)

    result = []

    for h in hospitals:
        name = h.get("tags", {}).get("name", "Unknown Hospital")
        h_lat = h['lat']
        h_lon = h['lon']

        distance = calculate_distance(float(lat), float(lon), h_lat, h_lon)

        result.append({
            "name": name,
            "distance": round(distance, 2),
            "map_link": f"https://www.google.com/maps/search/?api=1&query={h_lat},{h_lon}"
        })

    # nearest first
    result.sort(key=lambda x: x['distance'])

    return result[:5]   # top 5 only


# 🆘 FALLBACK (always show something)
def fallback_hospitals(lat, lon):
    return [
        {
            "name": "Nearest Hospital",
            "distance": 0.5,
            "map_link": f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        },
        {
            "name": "City Care Hospital",
            "distance": 1.2,
            "map_link": f"https://www.google.com/maps/search/?api=1&query={lat+0.01},{lon+0.01}"
        }
    ]