import json
import requests

from rmap import RMAPClient


BASE_URL = "http://localhost:5001"

client = RMAPClient(
    identity="RMAP_TEST",
    client_private_key_path="server/keys/rmap_test_private.asc",
    server_public_key_path="server/keys/server_pub.asc",
    verbose=True,
)

print("\n=== STEP 1: Build Message 1 ===")
msg1 = client.build_msg1()

print(json.dumps(msg1, indent=2))

print("\n=== STEP 2: Send Message 1 to server ===")
response1 = requests.post(
    f"{BASE_URL}/rmap-initiate-msg1",
    json=msg1,
)

print("HTTP:", response1.status_code)
print("Response:", response1.text)

response1.raise_for_status()

resp1 = response1.json()

print("\n=== STEP 3: Process Response 1 ===")
nonce_client, nonce_server = client.process_resp1(resp1)

print("nonceClient:", nonce_client)
print("nonceServer:", nonce_server)

print("\n=== STEP 4: Build Message 2 ===")
msg2 = client.build_msg2()

print(json.dumps(msg2, indent=2))

print("\n=== STEP 5: Send Message 2 to server ===")
response2 = requests.post(
    f"{BASE_URL}/rmap-getlink-msg2",
    json=msg2,
)

print("HTTP:", response2.status_code)
print("Response:", response2.text)

response2.raise_for_status()

resp2 = response2.json()

print("\n=== STEP 6: Process Response 2 ===")
link = client.process_resp2(resp2)

print("LINK:")
print(link)

print("\n=== EXPECTED BARE LINK ===")
print(client.expected_link)

print("\n=== HANDSHAKE SUCCESS ===")
