import requests


BASE_URL = "https://127.0.0.1:8443"

USERNAME = "V03Test"


response = requests.post(
    f"{BASE_URL}/auth/challenge",
    json={
        "username": USERNAME
    },
    verify=False,
    timeout=5
)


print("Status:", response.status_code)
print("Response:", response.text)


if response.status_code == 200:

    data = response.json()

    print("Username:", data["username"])
    print("Challenge:", data["challenge"])
    print("Challenge exists:", bool(data["challenge"]))

else:

    print("Challenge request FAILED")
print()
print("=" * 40)
print("UNKNOWN USER TEST")
print("=" * 40)


response = requests.post(
    f"{BASE_URL}/auth/challenge",
    json={
        "username": "UnknownUser"
    },
    verify=False,
    timeout=5
)


print("Status:", response.status_code)
print("Response:", response.text)


if response.status_code == 401:

    print("Unknown user rejected: PASS")

else:

    print("Unknown user rejected: FAIL")