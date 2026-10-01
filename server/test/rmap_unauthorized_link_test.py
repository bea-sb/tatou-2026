import requests

from rmap import RMAPClient
from rmap.crypto import decrypt_json

BASE_URL = "http://localhost:5001"

CLIENT_PRIVATE_KEY = "server/keys/rmap_test_private.asc"
SERVER_PUBLIC_KEY = "server/keys/server_pub.asc"

IDENTITY = "RMAP_TEST"


def main():
    print("\n=== UNAUTHORIZED-LINK SECURITY TEST ===")

    client = RMAPClient(
        identity=IDENTITY,
        client_private_key_path=CLIENT_PRIVATE_KEY,
        server_public_key_path=SERVER_PUBLIC_KEY,
        verbose=True,
    )

    # Step 1: Initiate a normal handshake.
    print("\nSTEP 1: Send msg1")

    msg1 = client.build_msg1()

    response = requests.post(
        f"{BASE_URL}/rmap-initiate-msg1",
        json=msg1,
        timeout=10,
    )

    print("HTTP status:", response.status_code)
    assert response.status_code == 200, response.text

    resp1 = response.json()

    # Step 2: Use the legitimate key in the test harness to
    # obtain the nonce needed for the next message.
    print("\nSTEP 2: Process resp1")

    client.process_resp1(resp1)

    print("nonceServer:", client.nonceServer)

    # Step 3: Construct msg2.
    # Based on the implementation, build_msg2 encrypts the
    # nonce using the SERVER public key. It does not sign
    # the message with the client's private key.
    print("\nSTEP 3: Build msg2 without client-key authentication")

    msg2 = client.build_msg2()

    # Step 4: Submit msg2 and observe whether the server
    # issues a session link.
    print("\nSTEP 4: Submit msg2")

    response2 = requests.post(
        f"{BASE_URL}/rmap-getlink-msg2",
        json=msg2,
        timeout=10,
    )

    print("HTTP status:", response2.status_code)

    if response2.status_code != 200:
        print("Server rejected msg2:", response2.text)
        print(
            "\nRESULT: The server rejected this request. "
            "Investigate the rejection before drawing a conclusion."
        )
        return

    resp2 = response2.json()

    # Decrypt the server's response with the legitimate key
    # in the test harness to confirm what the server issued.
    result = decrypt_json(
        resp2,
        client.clientPrivateKey,
        client._passphrase,
    )

    print("Decrypted server response:", result)

    if "result" in result:
        print("\nOBSERVATION: The server issued a session link.")
        print(
            "The msg2 construction shown above did not use "
            "the client's private key to authenticate msg2."
        )
        print(
            "This is evidence that the server's msg2 handling "
            "does not itself demonstrate client-key possession."
        )
    else:
        print("\nNo session link was present in the response.")


if __name__ == "__main__":
    main()