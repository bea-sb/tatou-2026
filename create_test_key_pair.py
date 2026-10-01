import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

uid = pgpy.PGPUID.new(
    "FCS_COP.1 Wrong-Key Test",
    email="fcs-cop1-test@example.invalid",
)

key.add_uid(
    uid,
    usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
    hashes=[HashAlgorithm.SHA256],
    ciphers=[SymmetricKeyAlgorithm.AES256],
    compression=[CompressionAlgorithm.ZLIB],
)

with open("server/keys/fcs_cop1_wrong_private.asc", "w") as f:
    f.write(str(key))

with open("server/keys/clients/fcs_cop1_wrong_public.asc", "w") as f:
    f.write(str(key.pubkey))
