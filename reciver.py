import socket
import json
import base64
import hashlib
import time
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

class SecureReceiver:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # Tạo cặp khóa RSA 1024-bit cho receiver
        self.receiver_key = RSA.generate(1024)
        self.receiver_public_key = self.receiver_key.publickey()
        
        # Lưu public key để sender có thể sử dụng
        self.save_public_key()
        
        self.sender_public_key = None
        self.session_key = None
        
    def save_public_key(self):
        """Lưu public key để sender sử dụng"""
        with open("receiver_public.pem", "wb") as f:
            f.write(self.receiver_public_key.export_key())
        print("Đã lưu public key tại receiver_public.pem")
    
    def connect_to_server(self):
        """Kết nối đến server trung gian"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"Đã kết nối đến server {self.server_host}:{self.server_port}")
            
            # Gửi message đăng ký là receiver
            register_msg = {"type": "register", "role": "receiver", "from": "receiver"}
            self.socket.send(json.dumps(register_msg).encode())
            print("Đã đăng ký với server là receiver")
            
            return True
        except Exception as e:
            print(f"Lỗi kết nối: {e}")
            return False
    
    def handle_handshake(self, message):
        """Xử lý handshake từ sender"""
        if message.get("data") == "Hello!" and message.get("from") == "sender":
            # Trả lời "Ready!"
            response = {"type": "handshake", "data": "Ready!", "from": "receiver"}
            self.socket.send(json.dumps(response).encode())
            print("Đã phản hồi handshake: Ready!")
            return True
        return False
    
    def handle_auth_key(self, message):
        """Xử lý xác thực và nhận session key"""
        try:
            # Lấy thông tin từ message
            metadata = message.get("metadata")
            signature = base64.b64decode(message.get("signature"))
            encrypted_session_key = base64.b64decode(message.get("encrypted_session_key"))
            sender_public_key_data = base64.b64decode(message.get("sender_public_key"))
            
            print(f"Metadata nhận được: {metadata}")
            print(f"Encrypted session key size: {len(encrypted_session_key)} bytes")
            
            # Import public key của sender
            self.sender_public_key = RSA.import_key(sender_public_key_data)
            print("Đã import public key của sender")
            
            # Verify chữ ký metadata
            h = SHA512.new(metadata.encode())
            try:
                pkcs1_15.new(self.sender_public_key).verify(h, signature)
                print("Xác thực chữ ký thành công!")
            except Exception as e:
                print(f"Xác thực chữ ký thất bại: {e}")
                self.send_error_response("Signature verification failed")
                return False
            
            # Giải mã session key
            try:
                from Crypto.Hash import SHA1
                cipher_rsa = PKCS1_OAEP.new(self.receiver_key, hashAlgo=SHA1)
                self.session_key = cipher_rsa.decrypt(encrypted_session_key)
                print(f"Đã giải mã session key thành công! Size: {len(self.session_key)} bytes")
            except Exception as e:
                print(f"Lỗi giải mã session key: {e}")
                self.send_error_response("Session key decryption failed")
                return False
            
            # Gửi xác nhận
            response = {"type": "response", "status": "auth_ok", "from": "receiver"}
            self.socket.send(json.dumps(response).encode())
            
            return True
            
        except Exception as e:
            print(f"Lỗi xử lý auth_key: {e}")
            import traceback
            traceback.print_exc()
            self.send_error_response(f"Auth error: {str(e)}")
            return False
    
    def handle_encrypted_file(self, message):
        """Xử lý file đã mã hóa"""
        try:
            # Lấy dữ liệu từ message
            nonce = base64.b64decode(message.get("nonce"))
            ciphertext = base64.b64decode(message.get("cipher"))
            tag = base64.b64decode(message.get("tag"))
            received_hash = message.get("hash")
            signature = base64.b64decode(message.get("sig"))
            
            print("Đang kiểm tra tính toàn vẹn...")
            
            # Kiểm tra hash
            hash_data = nonce + ciphertext + tag
            calculated_hash = hashlib.sha512(hash_data).hexdigest()
            
            if calculated_hash != received_hash:
                print("Kiểm tra hash thất bại!")
                self.send_error_response("Hash verification failed")
                return False
            
            print("Kiểm tra hash thành công!")
            
            # Kiểm tra chữ ký hash
            h = SHA512.new(received_hash.encode())
            try:
                pkcs1_15.new(self.sender_public_key).verify(h, signature)
                print("Xác thực chữ ký hash thành công!")
            except Exception:
                print("Xác thực chữ ký hash thất bại!")
                self.send_error_response("Hash signature verification failed")
                return False
            
            # Giải mã file bằng AES-GCM
            cipher_aes = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            
            try:
                plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
                print("Giải mã file thành công!")
            except Exception:
                print("Kiểm tra tag GCM thất bại!")
                self.send_error_response("GCM tag verification failed")
                return False
            
            # Lưu file
            output_filename = "received_report.txt"
            with open(output_filename, "wb") as f:
                f.write(plaintext)
            
            print(f"Đã lưu file: {output_filename}")
            
            # Hiển thị nội dung file
            try:
                with open(output_filename, "r", encoding="utf-8") as f:
                    content = f.read()
                    print("\n--- Nội dung file nhận được ---")
                    print(content)
                    print("--- Kết thúc nội dung file ---\n")
            except:
                print("Không thể hiển thị nội dung file (có thể file binary)")
            
            # Gửi ACK
            response = {"type": "response", "status": "ACK", "from": "receiver", 
                       "message": "File received and verified successfully"}
            self.socket.send(json.dumps(response).encode())
            
            return True
            
        except Exception as e:
            print(f"Lỗi xử lý file: {e}")
            self.send_error_response(f"File processing error: {str(e)}")
            return False
    
    def send_error_response(self, error_message):
        """Gửi phản hồi lỗi (NACK)"""
        response = {
            "type": "response", 
            "status": "NACK", 
            "from": "receiver",
            "message": error_message
        }
        self.socket.send(json.dumps(response).encode())
        print(f"Đã gửi NACK: {error_message}")
    
    def listen_for_messages(self):
        """Lắng nghe messages từ server"""
        try:
            while True:
                data = self.socket.recv(65536)  # Tăng buffer size
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode())
                    message_type = message.get("type")
                    
                    print(f"Nhận message loại: {message_type}")
                    
                    if message_type == "register_ack":
                        print("Server xác nhận đăng ký thành công!")
                        continue
                    
                    elif message_type == "handshake":
                        if not self.handle_handshake(message):
                            print("Handshake thất bại")
                            break
                    
                    elif message_type == "auth_key":
                        if not self.handle_auth_key(message):
                            print("Xác thực thất bại")
                            break
                    
                    elif message_type == "encrypted_file":
                        if not self.handle_encrypted_file(message):
                            print("Xử lý file thất bại")
                        # Không break ở đây để có thể nhận thêm file
                    
                    else:
                        print(f"Message type không xác định: {message_type}")
                
                except json.JSONDecodeError:
                    print("Lỗi decode JSON")
                except Exception as e:
                    print(f"Lỗi xử lý message: {e}")
        
        except Exception as e:
            print(f"Lỗi lắng nghe: {e}")
    
    def close_connection(self):
        """Đóng kết nối"""
        if self.socket:
            self.socket.close()
            print("Đã đóng kết nối")

def main():
    receiver = SecureReceiver()
    
    # Kết nối và lắng nghe
    if receiver.connect_to_server():
        print("Receiver đã sẵn sàng nhận dữ liệu...")
        print("Đang chờ sender khởi tạo giao dịch...")
        
        try:
            receiver.listen_for_messages()
        except KeyboardInterrupt:
            print("\nNgừng receiver...")
        finally:
            receiver.close_connection()

if __name__ == "__main__":
    main()