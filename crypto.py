import requests
import hashlib
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder

token = '000bebe02970e3b6faeeef4f38cf3a801e73164c'

def start():
    data = get_crypto()
    decrypt = decrypt_msg(data['cifrado'], data['numero_casas'])
    #decrypt = 'develper: an organism that turns coffee into code. unknown'
    cyphr = encrypt_msg(decrypt)
    data["decifrado"] = decrypt
    data["resumo_criptografico"] = cyphr
    print(data)
    send_crypto(data)


def decrypt_msg(msg, shift_value):
    decMsg = ''
    msg = msg.lower()
    print("shiftValue: ", shift_value)
    for char in msg:
        if char.isalpha():
            c = ord(char) - 97
            c -= shift_value
            c = c % 26
            decMsg += chr(c + 97)
        else:
            decMsg += char

    return decMsg


def encrypt_msg(msg):
    b = bytes(msg, 'utf-8')
    m = hashlib.sha1(b)
    s = m.hexdigest()
    return s


def send_crypto(json_data):
    uri = 'https://api.codenation.dev/v1/challenge/dev-ps/submit-solution?token={token}'.format(token=token)
    #save file to json
    with open('answer.json', 'w') as f:
        json.dump(json_data, f)

    multipart_form_data = MultipartEncoder(
        fields={
            'answer': ('answer.json', open('answer.json', 'rb'), 'text/plain')
        }
    )
    # headers
    headers = {'Content-Type': multipart_form_data.content_type}
    print(multipart_form_data)
    resp = requests.post(url=uri, data=multipart_form_data, headers=headers)
    print(resp.status_code)


def get_crypto():
    #enconding url
    uri = 'https://api.codenation.dev/v1/challenge/dev-ps/generate-data?token={token}'.format(token=token)

    # get from endpoint
    resp = requests.get(url=uri)

    # store json fil in a variable
    data = resp.json()

    return data


if __name__ == '__main__':
    start()
