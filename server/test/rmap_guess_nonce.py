import secrets
import os
from pathlib import Path
from rmap import RMAPClient,RMAPServer,ProtocolStateException
from rmap.crypto import encrypt_json

ROOT=Path(__file__).resolve().parents[1] #from server
KEYS=ROOT / "keys"  #directory inside root aka sevrer go to keys

def test_rmap_guess():
    #$env:PASSPHRASE="..."  
    server = RMAPServer(
        server_public_key_path=KEYS/"server_pub.asc",
        server_private_key_path=KEYS/"server_priv.asc",
        passphrase= os.environ.get("PASSPHRASE"),      # or None if the key isn't protected
        linkPrefix="http://localhost:5000/get-doc/",
        verbose=False,
    )

    server.loadIdentities(KEYS/"clients/")
    client = RMAPClient(
        identity="RMAP_TEST",
        server_public_key_path=KEYS/"server_pub.asc",
        client_private_key_path=KEYS/"rmap_test_private.asc",
        verbose=False,
    )

    # try to establish a legitimate msg1 to response1
    msg1 = client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)
    client.process_resp1(resp1)
    validNonce = client.nonceServer #we get the valid one for testing latr

    #confirm irs accepted
    validMsg2 = client.build_msg2()
    identity, expectedLink, resp2 = server.receiveMsg2(validMsg2)
    assert identity== client.identity
    assert expectedLink == client.expected_link

    #set the nr of attempts we want
    attempt = 10_000
    success = 0 #set it le zero

    #repeat for how many time we want for loop can have _
    for i in range(attempt): #python we dont need the i for i ++
        guessedNonce = secrets.randbits(64) #geberate random 64bit number
        print("validNonce:",validNonce, " vs this is guess:", guessedNonce)

        if guessedNonce == validNonce:
            success +=1
            continue

        fakeMsg2 = encrypt_json({"nonceServer" : guessedNonce}, server.serverPublicKey)

        try:
            server.receiveMsg2(fakeMsg2)
            success +=1
        except ProtocolStateException:
            pass
    print(f"\nNonce guesses attempted: {attempt}")
    print(f"Successful guesses: {success}")
    print(f"observed success rate: {success/attempt:.6f}") #show 6 digits after decimal point0.000000 f floating point number


        


    