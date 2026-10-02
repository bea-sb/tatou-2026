import json
import secrets
import requests

from rmap import RMAPClient


BASE_URL = "http://localhost:5000"

client = RMAPClient(
    identity="RMAP_TEST",
    client_private_key_path="server/keys/rmap_test_private.asc",
    server_public_key_path="server/keys/server_pub.asc",
    verbose=True,
)


def post_json(endpoint, payload):
    response = requests.post(
        f"{BASE_URL}{endpoint}",
        json=payload,
    )

    print(f"\nPOST {endpoint}")
    print(f"HTTP status: {response.status_code}")
    print("Response:")
    print(response.text)

    return response


print("\n=== FAU_GEN.1 TEST ===")
print("Testing audit generation for a rejected RMAP handshake message.")


# ------------------------------------------------------------
# STEP 1: Establish a normal RMAP handshake
# ------------------------------------------------------------

print("\n=== STEP 1: Build msg1 ===")

msg1 = client.build_msg1()

print(json.dumps(msg1, indent=2))


print("\n=== STEP 2: Send msg1 ===")

response1 = post_json(
    "/rmap-initiate-msg1",
    msg1,
)

response1.raise_for_status()

resp1 = response1.json()


print("\n=== STEP 3: Process resp1 ===")

nonce_client, nonce_server = client.process_resp1(resp1)

print(f"nonceClient = {nonce_client}")
print(f"nonceServer = {nonce_server}")


# ------------------------------------------------------------
# STEP 4: Deliberately invalidate the session nonce
# ------------------------------------------------------------

print("\n=== STEP 4: Replace nonceServer with invalid value ===")

original_nonce_server = client.nonceServer

invalid_nonce_server = secrets.randbits(64)

while invalid_nonce_server == original_nonce_server:
    invalid_nonce_server = secrets.randbits(64)

client.nonceServer = invalid_nonce_server

print(f"Original nonceServer: {original_nonce_server}")
print(f"Invalid nonceServer:  {invalid_nonce_server}")


# ------------------------------------------------------------
# STEP 5: Build msg2 using the invalid nonce
# ------------------------------------------------------------

print("\n=== STEP 5: Build invalid msg2 ===")

bad_msg2 = client.build_msg2()

print(json.dumps(bad_msg2, indent=2))


# ------------------------------------------------------------
# STEP 6: Submit invalid msg2
# ------------------------------------------------------------

print("\n=== STEP 6: Send invalid msg2 ===")

response2 = post_json(
    "/rmap-getlink-msg2",
    bad_msg2,
)


# ------------------------------------------------------------
# STEP 7: Record result
# ------------------------------------------------------------

print("\n=== STEP 7: Result ===")

if response2.status_code >= 400:
    print("PASS: The server rejected the invalid handshake message.")
else:
    print("UNEXPECTED: The server accepted the invalid handshake message.")

print(f"HTTP status = {response2.status_code}")
print(f"Response body = {response2.text}")
