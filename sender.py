import socket
import json
import base64
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import os

class SecureSender:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # Tạo cặp khóa RSA 1024-bit cho sender
        self.sender_key = RSA.generate(1024)
        self.sender_public_key = self.sender_key.publickey()
        
        # Load public key của receiver (giả sử đã có)
        self.receiver_public_key = None
        self.session_key = get_random_bytes(16)  # AES-128 key để phù hợp với RSA 1024-bit
        
    def load_receiver_public_key(self, key_file):
        """Load public key của receiver"""
        try:
            with open(key_file, 'rb') as f:
                self.receiver_public_key = RSA.import_key(f.read())
        except FileNotFoundError:
            print("Tạo public key mẫu cho receiver...")
            # Tạo key mẫu nếu không có
            temp_key = RSA.generate(1024)
            with open(key_file, 'wb') as f:
                f.write(temp_key.publickey().export_key())
            self.receiver_public_key = temp_key.publickey()
    
    def connect_to_server(self):
        """Kết nối đến server trung gian"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"Đã kết nối đến server {self.server_host}:{self.server_port}")
            
            # Gửi message đăng ký là sender
            register_msg = {"type": "register", "role": "sender", "from": "sender"}
            self.socket.send(json.dumps(register_msg).encode())
            print("Đã đăng ký với server là sender")
            
            return True
        except Exception as e:
            print(f"Lỗi kết nối: {e}")
            return False
    
    def handshake(self):
        """Bước 1: Handshake"""
        try:
            # Chờ xác nhận đăng ký trước
            response = json.loads(self.socket.recv(4096).decode())
            if response.get("type") != "register_ack":
                print("Không nhận được xác nhận đăng ký!")
                return False
            
            # Gửi "Hello!"
            message = {"type": "handshake", "data": "Hello!", "from": "sender"}
            self.socket.send(json.dumps(message).encode())
            
            # Nhận phản hồi
            response = json.loads(self.socket.recv(4096).decode())
            if response.get("data") == "Ready!":
                print("Handshake thành công!")
                return True
            else:
                print("Handshake thất bại!")
                return False
        except Exception as e:
            print(f"Lỗi handshake: {e}")
            return False
    
    def send_auth_and_key(self, filename, transaction_id):
        """Bước 2: Xác thực & Trao khóa"""
        try:
            timestamp = str(int(time.time()))
            
            # Tạo metadata
            metadata = f"{filename}|{timestamp}|{transaction_id}"
            
            # Ký metadata bằng RSA/SHA-512
            h = SHA512.new(metadata.encode())
            signature = pkcs1_15.new(self.sender_key).sign(h)
            
            # Mã hóa session key bằng RSA OAEP
            from Crypto.Hash import SHA1
            cipher_rsa = PKCS1_OAEP.new(self.receiver_public_key, hashAlgo=SHA1)
            
            # Kiểm tra kích thước session key có phù hợp không
            # max_encrypt_size = (1024 // 8) - 2 * (512 // 8) - 2  # ~62 bytes cho RSA 1024 + SHA512
            # if len(self.session_key) > max_encrypt_size:
            #     print(f"Session key quá lớn: {len(self.session_key)} bytes, max: {max_encrypt_size} bytes")
            #     # return False
            
            encrypted_session_key = cipher_rsa.encrypt(self.session_key)
            
            # Gửi dữ liệu
            auth_data = {
                "type": "auth_key",
                "from": "sender",
                "metadata": metadata,
                "signature": base64.b64encode(signature).decode(),
                "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
                "sender_public_key": base64.b64encode(self.sender_public_key.export_key()).decode()
            }
            
            self.socket.send(json.dumps(auth_data).encode())
            
            # Nhận xác nhận
            response = json.loads(self.socket.recv(4096).decode())
            if response.get("status") == "auth_ok":
                print("Xác thực và trao khóa thành công!")
                return True
            else:
                print("Xác thực thất bại!")
                return False
                
        except Exception as e:
            print(f"Lỗi xác thực: {e}")
            return False
    
    def encrypt_and_send_file(self, filename):
        """Bước 3: Mã hóa & Kiểm tra toàn vẹn"""
        try:
            # Đọc file
            with open(filename, 'rb') as f:
                file_data = f.read()
            
            # Tạo nonce
            nonce = get_random_bytes(16)
            
            # Mã hóa file bằng AES-GCM
            cipher_aes = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
            
            # Tính hash: SHA-512(nonce || ciphertext || tag)
            hash_data = nonce + ciphertext + tag
            file_hash = hashlib.sha512(hash_data).hexdigest()
            
            # Ký hash
            h = SHA512.new(file_hash.encode())
            signature = pkcs1_15.new(self.sender_key).sign(h)
            
            # Tạo gói tin
            packet = {
                "type": "encrypted_file",
                "from": "sender",
                "nonce": base64.b64encode(nonce).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
                "hash": file_hash,
                "sig": base64.b64encode(signature).decode()
            }
            
            self.socket.send(json.dumps(packet).encode())
            
            # Nhận phản hồi
            response = json.loads(self.socket.recv(4096).decode())
            if response.get("status") == "ACK":
                print("File đã được gửi và xác nhận thành công!")
                return True
            else:
                print(f"Gửi file thất bại: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"Lỗi mã hóa/gửi file: {e}")
            return False
    
    def close_connection(self):
        """Đóng kết nối"""
        if self.socket:
            self.socket.close()
            print("Đã đóng kết nối")

def main():
    # Tạo file report.txt mẫu nếu chưa có
    if not os.path.exists("report.txt"):
        with open("report.txt", "w", encoding="utf-8") as f:
            f.write("Báo cáo công ty\n")
            f.write("Ngày: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("Doanh thu quý 1: 1,000,000 VND\n")
            f.write("Tăng trưởng: 15%\n")
    
    sender = SecureSender()
    
    # Load public key của receiver
    sender.load_receiver_public_key("receiver_public.pem")
    
    # Kết nối và gửi file
    if sender.connect_to_server():
        transaction_id = f"TXN_{int(time.time())}"
        
        if (sender.handshake() and 
            sender.send_auth_and_key("report.txt", transaction_id) and
            sender.encrypt_and_send_file("report.txt")):
            print("Gửi file thành công!")
        else:
            print("Gửi file thất bại!")
        
        sender.close_connection()

if __name__ == "__main__":
    main()