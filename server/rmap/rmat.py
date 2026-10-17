import requests
from rmap import RMAPClient
import os

#tested groups 01, now ours
#remember 24 updated their flag needs updating in tatou as wll
#24 is unreachable as of right now
#nr 3 is getting us one too!!! YIPPIE

#5 no work yet but accesable by healthz

#9 rmap watermarked recieved :D

#11 reachable but no rmap

#13 rmap recieved

#reachable not rmap 15

TARGET_GROUP = "29"
MY_IDENTITY = "Group_07"

BASE_URL = (
    f"http://softsec-group-{TARGET_GROUP}.dsv.local.su.se:5000"
)

PASSPHRASE = os.environ.get("PASSPHRASE")

if not PASSPHRASE:
    raise RuntimeError("PASSPHRASE is empty")

CLIENT_PRIVATE_KEY = "../keys/server_priv.asc" #our private key
SERVER_PUBLIC_KEY = "../keys/clients/Group_29.asc" #theirs

#route requests through tunnel putty socks5 tunnel
session = requests.Session()
session.trust_env = False
session.proxies = {
    "http": "socks5h://127.0.0.1:1080",
    "https": "socks5h://127.0.0.1:1080",
}

#use real keys and initialize
client = RMAPClient(
    identity=MY_IDENTITY,
    client_private_key_path=CLIENT_PRIVATE_KEY,
    server_public_key_path=SERVER_PUBLIC_KEY,
    passphrase=PASSPHRASE,
)
#kom ihåg att sätta passphrasen för den verkar inte nå iguess?


#initiate handshake and num1
r1 = session.post(
    f"{BASE_URL}/api/rmap-initiate",
    json=client.build_msg1(),
    timeout=15,
)
print("Message 1 response:", r1.status_code, r1.text)
r1.raise_for_status()

#Process respince1 and make 2
nonce_client, nonce_server = client.process_resp1(r1.json())
print("Server response validated.")
print("Client nonce:", nonce_client)
print("Server nonce:", nonce_server)

msg2 = client.build_msg2()

#message2 possession server nonce proof
r2 = session.post(
    f"{BASE_URL}/api/rmap-get-link",
    json=msg2,
    timeout=15,
)
print("Message 2 response:", r2.status_code, r2.text)
r2.raise_for_status()

#response 2
#the link
link = client.process_resp2(r2.json())

print("\nRMAP handshake completed successfully.")
print("Returned link:", link)