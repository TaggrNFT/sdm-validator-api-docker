import os
import binascii


MASTER_KEY = [
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_0']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_1']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_2']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_3']),
    binascii.unhexlify(os.environ['NFC_MASTER_KEY_4'])
]

PBKDF_ROUNDS = int(os.environ['NFC_PBKDF_ROUNDS'])

TAG_HASH_KEY = binascii.unhexlify(os.environ['NFC_TAG_HASH_KEY'])
TAG_SECRET_KEY = binascii.unhexlify(os.environ['NFC_TAG_SECRET_KEY'])

SDMMAC_PARAM = ""
ENABLE_DEMO = os.environ.get('NFC_ENABLE_DEMO') == 'YES'
