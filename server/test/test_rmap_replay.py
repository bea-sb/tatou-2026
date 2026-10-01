import os
import pytest
from pathlib import Path
from dotenv import load_dotenv

from rmap.exceptions import ProtocolStateException
from rmap import RMAPClient, RMAPServer

load_dotenv()

def test_rmap_replay(): 
    REPO_ROOT = Path(__file__).resolve().parents[1]
    KEYS = REPO_ROOT / "keys"

    print("SERVER ROOT:", REPO_ROOT)
    print("KEYS:", KEYS)
    print("PUBLIC KEY:", KEYS / "server_pub.asc")
    print("PUBLIC KEY EXISTS:", (KEYS / "server_pub.asc").exists())
    print("PRIVATE KEY:", KEYS / "server_priv.asc")
    print("PRIVATE KEY EXISTS:", (KEYS / "server_priv.asc").exists())
    print("PASSPHRASE LOADED AND READY: ", os.environ.get("PASSPHRASE")is not None)
    
    server = RMAPServer(
        server_public_key_path=KEYS/"server_pub.asc",
        server_private_key_path=KEYS/"server_priv.asc",
        passphrase= os.environ.get("PASSPHRASE"),      # or None if the key isn't protected
        linkPrefix="http://localhost:5000/get-doc/",
        verbose=True,
    )
    server.loadIdentities(KEYS/"clients/")
    client = RMAPClient(
        identity="RMAP_TEST",
        server_public_key_path=KEYS/"server_pub.asc",
        client_private_key_path=KEYS/"rmap_test_private.asc",
        verbose=True,
    )

    msg1 =client.build_msg1()
    identity, resp1 = server.receiveMsg1(msg1)

    client.process_resp1(resp1)
    msg2=client.build_msg2()

    server.receiveMsg2(msg2)
    with pytest.raises(ProtocolStateException):
        server.receiveMsg2(msg2)
    #return


#so basically there could be a gap here with replay attack
#protocolstateexception: MSG2 already used