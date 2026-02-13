#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64, binascii, json, getpass, sys

if len(sys.argv) < 2:
	print(f"Usage:  showdb.py ENCRYPTED_AEGIS_JSON >PLAIN_JSON")
	sys.exit(1)

filename = sys.argv[1]
password = getpass.getpass("Password: ").encode("utf-8")
with open(filename) as f:
	raw = f.read()

aegis = json.loads(raw)
slot = aegis["header"]["slots"][0]
salt = salt = binascii.unhexlify(slot["salt"])
kdf = Scrypt(
	salt,
	length = 32,
	n = slot["n"],
	r = slot["r"],
	p = slot["p"],
)
slot_tag = binascii.unhexlify(slot["key_params"]["tag"])
slot_key = kdf.derive(password)
aes = AESGCM(slot_key)
slot_nonce = binascii.unhexlify(slot["key_params"]["nonce"])
encrypted_master_key = binascii.unhexlify(slot["key"])
ciphertext_with_tag = encrypted_master_key + slot_tag
master_key = aes.decrypt(slot_nonce, ciphertext_with_tag, None)
db_nonce = binascii.unhexlify(aegis["header"]["params"]["nonce"])
db_tag = binascii.unhexlify(aegis["header"]["params"]["tag"])
db_ciphertext = base64.b64decode(aegis["db"])
db_combined = db_ciphertext + db_tag
aes = AESGCM(master_key)
plaintext = aes.decrypt(db_nonce, db_combined, None)
data = json.loads(plaintext.decode())
print(json.dumps(data, indent=2))
