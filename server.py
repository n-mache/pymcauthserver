import socket #TCP通信とかをするやつ
import json #JSONをパースしてくれるやつ
import struct #バイナリを簡単にするやつ(?)
import threading #同時接続とかをするために使うやつ
from cryptography.hazmat.backends import default_backend #暗号化関係
from cryptography.hazmat.primitives.asymmetric import rsa, padding #暗号化関係
from cryptography.hazmat.primitives.ciphers import algorithms, modes #暗号化関係
from cryptography.hazmat.primitives import ciphers, serialization #暗号化関係
import os #OSの機能を使うためのやつ
import random #ランダム生成に使うやつ
import string #文字とかを使うやつ
import requests #HTTP通信をするためのやつ
import hashlib #ハッシュを生成するためのやつ
import uuid #UUIDをいろいろ扱えるやつ
import time #時間を扱うためのやつ

def encode_varint(num):
    res = b""   
    while num:
        b = num & 127
        num = num >> 7
        if num != 0:
            b |= 128
        res += bytes([b])
    return res

def decode_varint(data):
    val = 0
    shift = 0
    for d in data:
        val |= (d & 127) << shift
        if not (d & 128):break
        shift += 7
    return val

svhost = "0.0.0.0"
svport = 25565

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((svhost, svport))
server_socket.listen()
print(f"{svhost}:{svport}で接続を受け入れています。")

def handle_client(client, address):
    res = b""
    while True:
        r = client.recv(1)
        res += r
        if not r[0] & 128:break
    size = decode_varint(res)
    res = client.recv(size)
    recv = b""
    pos = 0
    for r in res:
        recv += bytes([r])
        pos += 1
        if not r & 128:break
    packet_id = decode_varint(recv)
    if packet_id != 0:
        client.close()
        return
    recv = b""
    for r in res[pos:]:
        recv += bytes([r])
        pos += 1
        if not r & 128:break
    protocol_version = decode_varint(recv)
    recv = b""
    for r in res[pos:]:
        recv += bytes([r])
        pos += 1
        if not r & 128:break
    size = decode_varint(recv)
    addr = res[pos:pos+size].decode("utf-8")
    pos += size
    port = struct.unpack(">H", res[pos:pos+2])[0]
    pos += 2
    recv = b""
    for r in res[pos:]:
        recv += bytes([r])
        pos += 1
        if not r & 128:break
    next_state = decode_varint(recv)
    if next_state != 1 and next_state != 2:
        client.close()
        return
    if next_state == 1:
        res = b""
        while True:
            r = client.recv(1)
            res += r
            if not r[0] & 128:break
        size = decode_varint(res)
        res = client.recv(size)
        if res != b"\x00":
            client.close()
            return
        data = json.dumps({"version": {"name": "認証サーバー", "protocol": protocol_version}, "players": {"max": 1, "online": 0}, "description": {"text": "認証サーバー"}}).encode()
        data = b"\x00"+encode_varint(len(data))+data
        client.send(encode_varint(len(data))+data)
        pos = 0
        res = b""
        while True:
            r = client.recv(1)
            res += r
            pos += 1
            if not r[0] & 128:break
        size = decode_varint(res)
        res = client.recv(size)
        if res[0] != 1:
            client.close()
            return
        data = res
        data = encode_varint(len(data))+data
        client.send(data)
        client.close()
    if next_state == 2:
        res = b""
        while True:
            r = client.recv(1)
            res += r
            if not r[0] & 128:break
        size = decode_varint(res)
        res = client.recv(size)
        pos = 0
        if res[0] != 0:
            client.close()
            return
        pos += 1
        recv = b""
        for r in res[pos:]:
            recv += bytes([r])
            pos += 1
            if not r & 128:break
        size = decode_varint(recv)
        username = res[pos:pos+size].decode("utf-8")
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        public_key = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        verify_token = os.urandom(4)
        server_id = ("".join(random.choices(string.ascii_lowercase+string.digits,k=10))).encode('ascii')
        data = b"\x01"+encode_varint(len(server_id))+server_id+encode_varint(len(public_key))+public_key+encode_varint(len(verify_token))+verify_token
        data = encode_varint(len(data))+data
        client.send(data)
        res = b""
        while True:
            r = client.recv(1)
            res += r
            if not r[0] & 128:break
        size = decode_varint(res)
        res = client.recv(size)
        if res[0] != 1:
            client.close()
            return
        pos = 1
        recv = b""
        for r in res[pos:]:
            recv += bytes([r])
            pos += 1
            if not r & 128:break
        size = decode_varint(recv)
        shared_secret = res[pos:pos+size]
        shared_secret = key.decrypt(shared_secret, padding.PKCS1v15())
        pos += size
        recv = b""
        for r in res[pos:]:
            pos += 1
            if len(recv) == 0 and r == 0:continue
            recv += bytes([r])
            if not r & 128:break
        size = decode_varint(recv)
        client_verify_token = res[pos:pos+size]
        client_verify_token = key.decrypt(client_verify_token, padding.PKCS1v15())
        if verify_token != client_verify_token:
            client.close()
            return
        cipher = ciphers.Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        hash = hashlib.sha1()
        hash.update(server_id)
        hash.update(shared_secret)
        hash.update(public_key)
        hash = int(hash.hexdigest(), 16)
        if hash >> 156 & 8:
            hash = "-"+format(hash*-1 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,"x")
        else:
            hash = format(hash,"x")
        has_joined = requests.get("https://sessionserver.mojang.com/session/minecraft/hasJoined",params={"username":username,"serverId":hash})
        has_joined_response = {}
        try:has_joined_response = has_joined.json()
        except:pass
        if has_joined.status_code != 200 or not "id" in has_joined_response:
            data = json.dumps({"text": "認証できませんでした。", "color": "red"}).encode()
            data = b"\x00"+encode_varint(len(data))+data
            data = encode_varint(len(data))+data
            data = encryptor.update(data)
            client.send(data)
            client.close()
            return
        verify_code = "".join(random.choices(string.digits,k=6))
        print(has_joined_response["name"]+" ("+has_joined_response["id"]+") に認証コードを発行しました。")
        data = json.dumps({"text": "§a認証コードを発行しました§r\n§bユーザー名:§r §f"+has_joined_response["name"]+"§r\n§b認証コード:§r §f"+verify_code+"§r"}).encode()
        data = b"\x00"+encode_varint(len(data))+data
        data = encode_varint(len(data))+data
        data = encryptor.update(data)
        client.send(data)
        client.close()
        # 認証コードを保存する処理をここへ
        # ファイルに保存する例
        with open("mcauths/"+has_joined_response["id"], "w") as f:
            f.write(json.dumps({"code": verify_code, "expire": time.time()+600}))

while True:
    client, address = server_socket.accept()
    threading.Thread(target=handle_client,args=(client, address,)).start()
