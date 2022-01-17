import argparse
import binascii
import io

from flask import Flask, request, jsonify, render_template
from werkzeug.exceptions import BadRequest

from libsdm import decrypt_sun_message, InvalidMessage
from derive import derive_tag_key, calculate_tag_secret, unwrap_uid, wrap_uid

from config import ENABLE_DEMO

app = Flask(__name__)


@app.route('/')
def sdm_main():
    return jsonify({"message": "Internal SDM validator API for NTAG 424 DNA."})


def read_and_unhex(s: io.StringIO, desired_len: int):
    data = s.read(desired_len)

    if len(data) != desired_len:
        raise BadRequest("Invalid parameters.")

    try:
        return binascii.unhexlify(data)
    except binascii.Error:
        raise BadRequest("Invalid parameters.")


def internal_validate():
    try:
        s = io.StringIO(request.args["enc"])

        tag_hash = read_and_unhex(s, 32)
        picc_enc_data = read_and_unhex(s, 32)
        enc_file_data = read_and_unhex(s, 32)
        sdmmac = read_and_unhex(s, 16)
    except BadRequest:
        return {"valid": False, "tag": None}

    try:
        res = decrypt_sun_message(sdm_meta_read_key=derive_tag_key(tag_hash, 1),
                                  sdm_file_read_key=derive_tag_key(tag_hash, 2),
                                  picc_enc_data=picc_enc_data,
                                  sdmmac=sdmmac,
                                  enc_file_data=enc_file_data)
    except InvalidMessage:
        return {"valid": False, "tag": None}

    picc_data_tag, uid, read_ctr_num, file_data = res

    buf = io.BytesIO(file_data)
    tag_type = buf.read(2)
    tt_status = buf.read(2)
    tag_secret = buf.read(12)

    if tag_secret.decode('ascii', 'replace') != calculate_tag_secret(tag_hash):
        return {"valid": False, "tag": None}

    tt_status_s = "not_supported"

    if tag_type == b"TT":
        if tt_status == b"CC":
            tt_status_s = "secure"
        elif tt_status == b"OC":
            tt_status_s = "tampered_closed"
        elif tt_status == b"OO":
            tt_status_s = "tampered_open"
        else:
            tt_status_s = "unknown"

    return {
        "valid": True,
        "tag": {
            "uid": uid.hex().upper(),
            "read_ctr": read_ctr_num,
            "tt_status": tt_status_s
        }
    }


@app.route('/api/validate')
def sdm_validate():
    return jsonify(internal_validate())


@app.route('/api/unwrap_uid')
def sdm_unwrap_uid():
    try:
        real_uid = unwrap_uid(request.args['wrapped_uid'])
    except (binascii.Error, RuntimeError):
        return jsonify({"valid": False, "real_uid": None})

    return jsonify({"valid": True, "real_uid": real_uid.hex().upper()})


@app.route('/demo')
def sdm_demo():
    if not ENABLE_DEMO:
        raise BadRequest()

    return render_template('demo.html', res=internal_validate())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?',
                        help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?',
                        help='port to listen on')

    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
