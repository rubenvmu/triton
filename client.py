import socket
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

MAINTENANCE_KEY = b"TRICONEX-MAINT-SCH-34-Sx0!pqB.rT"

def generate_dynamic_token():
    """Genera un token de autenticación dinámico"""
    time_factor = int(time.time() / 300)
    system_salt = 0xCAFE 
    return hashlib.sha256(f"{time_factor}{system_salt}".encode()).hexdigest()[:8]

def encrypt_response(token, timestamp):
    """Cifra la respuesta del cliente"""
    cipher = AES.new(MAINTENANCE_KEY, AES.MODE_ECB)
    response = f"{token}|{timestamp}".encode()
    return cipher.encrypt(pad(response, AES.block_size))

def send_command(client_id):
    """Conecta al servidor y deshabilita las redundancias"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect(('localhost', 502)) 
           
            token = generate_dynamic_token()
            timestamp = str(time.time())
            encrypted_response = encrypt_response(token, timestamp)
            s.sendall(encrypted_response)
            
            session_key = s.recv(1024)
            if not session_key:
                return

            cipher = AES.new(session_key, AES.MODE_ECB)

            disable_maintenance = f"DISABLE_MAINTENANCE {MAINTENANCE_KEY.decode()}"  # Decode bytes to string
            encrypted_maintenance = cipher.encrypt(pad(disable_maintenance.encode(), AES.block_size))
            s.sendall(encrypted_maintenance)
            print(s.recv(1024).decode())

            disable_safety = "DISABLE_SAFETY"
            encrypted_safety = cipher.encrypt(pad(disable_safety.encode(), AES.block_size))
            s.sendall(encrypted_safety)  
            print(s.recv(1024).decode()) 

        except Exception as e:
            print(f"Error: {e}")
        finally:
            print("[*] Connection closed")

if __name__ == "__main__":
    client_id = "client_1"  
    send_command(client_id)