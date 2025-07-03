import socket
import threading
import json
import time
from datetime import datetime
import os

class IntermediateServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.log_file = "transaction_log.txt"
        self.clients = {}  # Lưu thông tin clients
        
    def log_transaction(self, event, client_info="", additional_info=""):
        """Ghi log giao dịch với timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {event}"
        if client_info:
            log_entry += f" - {client_info}"
        if additional_info:
            log_entry += f" - {additional_info}"
        
        print(log_entry)
        
        # Ghi vào file log
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    
    def start_server(self):
        """Khởi động server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            self.log_transaction("SERVER_START", f"Server khởi động tại {self.host}:{self.port}")
            
            print(f"Server đang lắng nghe tại {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = self.socket.accept()
                self.log_transaction("CLIENT_CONNECT", f"Client kết nối từ {client_address}")
                
                # Tạo thread xử lý client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            self.log_transaction("SERVER_ERROR", f"Lỗi server: {e}")
            print(f"Lỗi server: {e}")
    
    def handle_client(self, client_socket, client_address):
        """Xử lý client kết nối"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            while True:
                # Nhận dữ liệu từ client
                data = client_socket.recv(65536)  # Tăng buffer size cho file lớn
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode())
                    message_type = message.get("type")
                    sender = message.get("from", "unknown")
                    
                    self.log_transaction(
                        "MESSAGE_RECEIVED", 
                        f"From {client_id} ({sender})",
                        f"Type: {message_type}"
                    )
                    
                    # Xử lý theo loại message
                    if message_type == "register":
                        self.handle_register(client_socket, client_id, message)
                    
                    elif message_type == "handshake":
                        self.handle_handshake(client_socket, client_id, message)
                    
                    elif message_type == "auth_key":
                        self.handle_auth_key(client_socket, client_id, message)
                    
                    elif message_type == "encrypted_file":
                        self.handle_encrypted_file(client_socket, client_id, message)
                    
                    elif message_type == "response":
                        self.handle_response(client_socket, client_id, message)
                    
                    else:
                        self.log_transaction(
                            "UNKNOWN_MESSAGE", 
                            f"From {client_id}",
                            f"Unknown type: {message_type}"
                        )
                
                except json.JSONDecodeError:
                    self.log_transaction("JSON_ERROR", f"From {client_id}", "Invalid JSON format")
                except Exception as e:
                    self.log_transaction("HANDLE_ERROR", f"From {client_id}", f"Error: {e}")
        
        except Exception as e:
            self.log_transaction("CLIENT_ERROR", f"Client {client_id}", f"Error: {e}")
        
        finally:
            client_socket.close()
            self.log_transaction("CLIENT_DISCONNECT", f"Client {client_id} ngắt kết nối")
    
    def handle_register(self, client_socket, client_id, message):
        """Xử lý đăng ký client"""
        role = message.get("role")
        if role in ["sender", "receiver"]:
            self.clients[client_id] = {"type": role, "socket": client_socket}
            self.log_transaction(
                "CLIENT_REGISTERED", 
                f"Client {client_id} đăng ký là {role}"
            )
            
            # Gửi xác nhận đăng ký
            response = {"type": "register_ack", "status": "success"}
            client_socket.send(json.dumps(response).encode())
        else:
            self.log_transaction("INVALID_ROLE", f"Client {client_id} gửi role không hợp lệ: {role}")
    
    def handle_handshake(self, client_socket, client_id, message):
        """Xử lý handshake"""
        sender = message.get("from")
        data = message.get("data")
        
        if sender == "sender" and data == "Hello!":
            # Lưu thông tin sender
            self.clients[client_id] = {"type": "sender", "socket": client_socket}
            
            # Chuyển tiếp đến receiver (giả sử receiver đã kết nối)
            receiver_client = self.find_receiver()
            if receiver_client:
                receiver_client["socket"].send(json.dumps(message).encode())
                self.log_transaction(
                    "MESSAGE_FORWARDED", 
                    f"Handshake từ sender {client_id} đến receiver"
                )
            else:
                self.log_transaction("NO_RECEIVER", "Không tìm thấy receiver")
        
        elif sender == "receiver" and data == "Ready!":
            # Lưu thông tin receiver
            self.clients[client_id] = {"type": "receiver", "socket": client_socket}
            
            # Chuyển tiếp đến sender
            sender_client = self.find_sender()
            if sender_client:
                sender_client["socket"].send(json.dumps(message).encode())
                self.log_transaction(
                    "MESSAGE_FORWARDED", 
                    f"Ready từ receiver {client_id} đến sender"
                )
    
    def handle_auth_key(self, client_socket, client_id, message):
        """Xử lý xác thực và trao khóa"""
        # Chuyển tiếp đến receiver
        receiver_client = self.find_receiver()
        if receiver_client:
            receiver_client["socket"].send(json.dumps(message).encode())
            self.log_transaction(
                "AUTH_KEY_FORWARDED", 
                f"Từ sender {client_id} đến receiver",
                f"Metadata: {message.get('metadata', 'N/A')}"
            )
        else:
            self.log_transaction("NO_RECEIVER", "Không thể chuyển tiếp auth_key")
    
    def handle_encrypted_file(self, client_socket, client_id, message):
        """Xử lý file đã mã hóa"""
        # Chuyển tiếp đến receiver
        receiver_client = self.find_receiver()
        if receiver_client:
            # Log thông tin file
            cipher_size = len(message.get("cipher", ""))
            self.log_transaction(
                "FILE_FORWARDED", 
                f"Từ sender {client_id} đến receiver",
                f"File size (encrypted): {cipher_size} bytes"
            )
            
            receiver_client["socket"].send(json.dumps(message).encode())
        else:
            self.log_transaction("NO_RECEIVER", "Không thể chuyển tiếp encrypted file")
    
    def handle_response(self, client_socket, client_id, message):
        """Xử lý phản hồi từ receiver"""
        # Chuyển tiếp đến sender
        sender_client = self.find_sender()
        if sender_client:
            sender_client["socket"].send(json.dumps(message).encode())
            self.log_transaction(
                "RESPONSE_FORWARDED", 
                f"Từ receiver {client_id} đến sender",
                f"Status: {message.get('status', 'N/A')}"
            )
        else:
            self.log_transaction("NO_SENDER", "Không thể chuyển tiếp response")
    
    def find_sender(self):
        """Tìm client sender"""
        for client_id, client_info in self.clients.items():
            if client_info.get("type") == "sender":
                return client_info
        return None
    
    def find_receiver(self):
        """Tìm client receiver"""
        for client_id, client_info in self.clients.items():
            if client_info.get("type") == "receiver":
                return client_info
        return None
    
    def stop_server(self):
        """Dừng server"""
        if self.socket:
            self.socket.close()
            self.log_transaction("SERVER_STOP", "Server đã dừng")

def main():
    server = IntermediateServer()
    
    try:
        print("Khởi động Server trung gian...")
        print("Nhấn Ctrl+C để dừng server")
        server.start_server()
    except KeyboardInterrupt:
        print("\nDừng server...")
        server.stop_server()
    except Exception as e:
        print(f"Lỗi: {e}")
        server.stop_server()

if __name__ == "__main__":
    main()