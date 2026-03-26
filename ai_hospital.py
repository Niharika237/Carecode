import requests
import math

# 🌍 Distance calculation (accurate)
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km

    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)

    a = math.sin(d_lat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c


# 🏥 Get nearby hospitals
def get_nearby_hospitals(lat, lon):
    url = "https://overpass-api.de/api/interpreter"

    query = f"""
    [out:json];
    node["amenity"="hospital"](around:5000,{lat},{lon});
    out;
    """

    try:
        res = requests.get(url, params={'data': query}, timeout=10)

        if res.status_code != 200:
            print("API Error:", res.status_code)
            return []

        data = res.json()

    except Exception as e:
        print("Overpass API failed:", e)
        return []

    hospitals = data.get("elements", [])

    result = []

    for h in hospitals:
        name = h.get("tags", {}).get("name", "Unknown Hospital")
        h_lat = h['lat']
        h_lon = h['lon']

        distance = calculate_distance(float(lat), float(lon), h_lat, h_lon)

        result.append({
            "name": name,
            "lat": h_lat,
            "lon": h_lon,
            "distance": round(distance, 2)
        })

    # nearest first
    result.sort(key=lambda x: x['distance'])

    return result