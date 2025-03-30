import socket
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import secrets

# Clave AES-256 (32 bytes)
MAINTENANCE_KEY = b"TRICONEX-MAINT-SCH-34-Sx0!pqB.rT"

def generate_dynamic_token():
    """Genera un token de autenticación dinámico"""
    time_factor = int(time.time() / 300)
    system_salt = 0xCAFE  # Este valor debe ser el que se usa en el sistema
    return hashlib.sha256(f"{time_factor}{system_salt}".encode()).hexdigest()[:8]

def encrypt_response(token, timestamp):
    """Cifra la respuesta del cliente"""
    cipher = AES.new(MAINTENANCE_KEY, AES.MODE_ECB)
    response = f"{token}|{timestamp}".encode()
    return cipher.encrypt(pad(response, AES.block_size))

def send_command(client_id, command):
    """Conecta al servidor y envía un comando"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 502))  # Cambia 'localhost' si es necesario

        # Generar el token y timestamp
        token = generate_dynamic_token()
        timestamp = str(time.time())
        encrypted_response = encrypt_response(token, timestamp)

        # Enviar la respuesta cifrada para autenticación
        s.sendall(encrypted_response)

        # Esperar respuesta del servidor
        session_key = s.recv(1024)
        if not session_key:
            print("Autenticación fallida.")
            return

        # Cifrar el comando
        cipher = AES.new(session_key, AES.MODE_ECB)
        encrypted_command = cipher.encrypt(pad(command.encode(), AES.block_size))

        # Enviar el comando cifrado
        s.sendall(encrypted_command)

        # Esperar la respuesta del servidor
        response = s.recv(1024)
        print("Respuesta del servidor:", response.decode())

if __name__ == "__main__":
    client_id = "client_1"  # Identificador único para el cliente
    command = "GET_FLAG"  # Comando para obtener la flag
    send_command(client_id, command)