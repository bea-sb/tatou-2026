import requests

from rmap import RMAPClient
from rmap.crypto import load_key
from rmap.crypto import decrypt_json
from rmap import DecryptionException


BASE_URL = "http://localhost:5000"

CLIENT_PRIVATE_KEY = "server/keys/rmap_test_private.asc"
SERVER_PUBLIC_KEY = "server/keys/server_pub.asc"

# Another entities private key
WRONG_PRIVATE_KEY = "server/keys/fcs_cop1_wrong_private.asc"


client = RMAPClient(
    identity="RMAP_TEST",
    client_private_key_path=CLIENT_PRIVATE_KEY,
    server_public_key_path=SERVER_PUBLIC_KEY,
    verbose=True,
)


print("\n=== FCS_COP.1 REGRESSION TEST ===")
print("Testing that an RMAP response can only be decrypted")
print("with the private key corresponding to the registered identity.")


# ------------------------------------------------------------
# STEP 1: Build legitimate msg1
# ------------------------------------------------------------

print("\n=== STEP 1: Build msg1 ===")

msg1 = client.build_msg1()


# ------------------------------------------------------------
# STEP 2: Send msg1 to the server
# ------------------------------------------------------------

print("\n=== STEP 2: Send msg1 ===")

response = requests.post(
    f"{BASE_URL}/rmap-initiate-msg1",
    json=msg1,
)

print(f"HTTP status: {response.status_code}")

if response.status_code != 200:
    print(f"Response: {response.text}")

response.raise_for_status()

resp1 = response.json()


# ------------------------------------------------------------
# STEP 3: Verify correct private key can decrypt resp1 (Expected behaviour of working RMAP)
# ------------------------------------------------------------

print("\n=== STEP 3: Decrypt resp1 with RMAP_TEST private key ===")

nonce_client, nonce_server = client.process_resp1(resp1)

print("PASS: RMAP_TEST private key successfully decrypted resp1.")
print(f"nonceClient = {nonce_client}")
print(f"nonceServer = {nonce_server}")


# ------------------------------------------------------------
# STEP 4: Load a different private key (E.g of possible attacker)
# ------------------------------------------------------------

print("\n=== STEP 4: Load server private key ===")

server_private_key = load_key(WRONG_PRIVATE_KEY)

print("Other entities private key loaded.")


# ------------------------------------------------------------
# STEP 5: Attempt to decrypt RMAP_TEST response
#         with the wrong private key
# ------------------------------------------------------------

print("\n=== STEP 5: Attempt decryption with wrong private key ===")

try:
    decrypt_json(
        resp1,
        server_private_key,
    )

except DecryptionException as e:
    print("PASS: Other entities private key could not decrypt resp1.")
    print(f"DecryptionException: {e}")

else:
    print("FAIL: Other entitites private key successfully decrypted resp1.")
    raise AssertionError(
        "RMAP response encrypted for RMAP_TEST was decryptable "
        "using the other entities private key."
    )


print("\n=== TEST RESULT ===")
print("PASS: FCS_COP.1 recipient-private-key regression test passed.")

