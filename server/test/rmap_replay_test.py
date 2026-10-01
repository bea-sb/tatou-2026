import requests

from rmap import RMAPClient
from rmap.crypto import decrypt_json

BASE_URL = "http://localhost:5001"

CLIENT_PRIVATE_KEY = "server/keys/rmap_test_private.asc"
SERVER_PUBLIC_KEY = "server/keys/server_pub.asc"

IDENTITY = "RMAP_TEST"


def main():
    print("\n=== RMAP REPLAY ATTACK TEST ===")
    print("Testing whether the server accepts the same msg2 twice.")

    client = RMAPClient(
        identity=IDENTITY,
        client_private_key_path=CLIENT_PRIVATE_KEY,
        server_public_key_path=SERVER_PUBLIC_KEY,
        verbose=True,
    )

    # STEP 1: Initiate a fresh handshake.
    print("\nSTEP 1: Send msg1")

    msg1 = client.build_msg1()

    response1 = requests.post(
        f"{BASE_URL}/rmap-initiate-msg1",
        json=msg1,
        timeout=10,
    )

    print("HTTP status:", response1.status_code)
    assert response1.status_code == 200, response1.text

    resp1 = response1.json()

    # STEP 2: Process resp1 and obtain the server nonce.
    print("\nSTEP 2: Process resp1")

    client.process_resp1(resp1)

    print("Received nonceServer:", client.nonceServer)

    # STEP 3: Construct msg2 ONCE in the legitimate handshake.
    print("\nSTEP 3: Build msg2")

    msg2 = client.build_msg2()

    # STEP 4: Submit msg2 for the first time.
    print("\nSTEP 4: Submit msg2 (original request)")

    first = requests.post(
        f"{BASE_URL}/rmap-getlink-msg2",
        json=msg2,
        timeout=10,
    )

    print("First response status:", first.status_code)

    assert first.status_code == 200, (
        "The original msg2 was not accepted: "
        f"{first.status_code} {first.text}"
    )

    first_result = decrypt_json(
        first.json(),
        client.clientPrivateKey,
        client._passphrase,
    )

    original_link = first_result.get("result")

    assert original_link, (
        "Original response did not contain a session link."
    )

    print("Original request issued a session link.")

    # STEP 5: Replay the EXACT SAME msg2 as an attacker using replay attack would.
    # Do not rebuild msg2 or start another handshake.
    print("\nSTEP 5: Replay the exact same msg2")

    second = requests.post(
        f"{BASE_URL}/rmap-getlink-msg2",
        json=msg2,
        timeout=10,
    )

    print("Replay response status:", second.status_code)

    if second.status_code != 200:
        print("Replay rejected:", second.text)
        print("\nPASS: Server rejected the replayed msg2.")
        return

    replay_result = decrypt_json(
        second.json(),
        client.clientPrivateKey,
        client._passphrase,
    )

    replay_link = replay_result.get("result")

    if replay_link:
        print("Replay was accepted and a session link was returned.")

        if replay_link == original_link:
            print("The replay returned the same session link.")
        else:
            print("The replay returned a different session link.")

        print(
            "\nFAIL: The server accepted a previously accepted msg2. "
            "Investigate replay protection."
        )
    else:
        print(
            "\nThe server returned HTTP 200, but no session link "
            "was present in the decrypted response."
        )


if __name__ == "__main__":
    main()