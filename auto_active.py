from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_v1_5
from Crypto import Random
import base64
import requests


def _send_public_key(cam_ip, private_key):
    public_key = private_key.publickey()
    public_key_bin = bytearray.fromhex('{:0192x}'.format(public_key.n))
    public_key_str = base64.b16encode(public_key_bin).lower()
    public_key_base64_encoded = base64.b64encode(public_key_str)
    data = "<?xml version='1.0' encoding='UTF-8'?><PublicKey><key>" + public_key_base64_encoded.decode('utf-8') + "</key></PublicKey>"
    response = requests.post('http://'+cam_ip+'/ISAPI/Security/challenge', data=data.encode('utf-8'))
    ret = response.text
    key = ret[ret.find('<key>') + 5:ret.find('</key>')]
    return key


def _get_random_key_text(key, private_key):
    random_key_encoded = base64.b64decode(key)
    random_key_bin = base64.b16decode(random_key_encoded.upper())
    random = Random.new().read(256)
    p_key = PKCS1_v1_5.new(private_key)
    random_key_text = p_key.decrypt(random_key_bin, random)
    return random_key_text.decode('utf-8')


def _encrypt_password(random_key_text, password):
    random_key = base64.b16decode(random_key_text.upper())
    new_password = password
    #补齐
    for i in range(len(new_password), 16):
        new_password += chr(0)
    # AES.MODE_ECB
    cipher = AES.new(random_key, AES.MODE_ECB)
    #random_key_text 前16字节+ 密码
    part1 = cipher.encrypt(random_key_text[:16].encode('utf-8'))
    part2 = cipher.encrypt(new_password.encode('utf-8'))
    pass_encrypted = part1 + part2
    pass_encrypted_encoded = base64.b64encode(base64.b16encode(pass_encrypted).lower())
    return pass_encrypted_encoded.decode('utf-8')


def _activation_request(cam_ip, pass_encrypted):
    data = "<?xml version='1.0' encoding='UTF-8'?><ActivateInfo><password>"+pass_encrypted+"</password></ActivateInfo>"
    response = requests.put('http://'+cam_ip+'/ISAPI/System/activate', data=data.encode('utf-8'),)
    return response.status_code,response.text


def _is_active(cam_ip):
    response = requests.get('http://'+cam_ip+'/SDK/activateStatus')
    ret = response.text
    ret = ret[ret.find('<Activated>') + 11:ret.find('</Activated>')]
    if ret =='false':
        return False
    return True


def set_activation(cam_ip, password):

    if not _is_active(cam_ip):
        rsa_key = RSA.generate(1024)
        answer_text = _send_public_key(cam_ip, rsa_key)
        random_key_text = _get_random_key_text(answer_text, rsa_key)
        if random_key_text:
            pass_encrypted_encoded = _encrypt_password(random_key_text, password)
            code,ret = _activation_request(cam_ip, pass_encrypted_encoded)
            if code == 200:
              print("Active Camera: success")
            else:
              print("Active Camera: error",ret)
        else:
            print("Active Camera: error")
    else:
        print("Camera is Active")
        return None

    return password

# set_activation('192.168.31.90','asdf1234')


