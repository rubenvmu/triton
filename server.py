#!/usr/bin/env python3
# Servidor Triconex Safety Instrumented System v4.7 - Backdoor Challenge

from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.transaction import ModbusSocketFramer

import time
from datetime import datetime
import random
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import socket

# ============== CONFIGURACIÓN DEL SISTEMA ==============
MODBUS_PORT = 502
FLAG = "flag{tr1c0n1x_0v3rr1d3_2023}"
MAINTENANCE_KEY = b"TRICONEX-MAINT-SCH-34-Sx0!pqB.rT"
SESSION_TIMEOUT = 300

class SafetySystem:
    def __init__(self):
        """Sistema de seguridad industrial con solo 2 redundancias: 
           MAINTENANCE y SAFETY. Deben deshabilitarse ambas para obtener la flag."""
        self.holding_regs = [0] * 200
        self.coils = [False] * 200
        self.input_regs = [random.randint(0, 9999) for _ in range(200)]
        self.system_state = "OPERATIONAL"
        # Solo dos redundancias: MAINTENANCE y SAFETY
        self.redundancy = ["MAINTENANCE", "SAFETY"]
        self._initialize_system()
        self.audit_log = []
        self.last_maintenance = datetime.now()

    def _initialize_system(self):
        """Configuración inicial del sistema"""
        self.holding_regs[0] = 0x900D
        self.holding_regs[1] = 0x0001
        self.holding_regs[2] = 0xCAFE
        
        for i in range(10, 15):
            self.coils[i] = False

    def log_event(self, event, severity="INFO"):
        """Registro de eventos de auditoría"""
        timestamp = datetime.now().strftime("2017-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{severity}] {event}"
        self.audit_log.append(log_entry)
        if len(self.audit_log) > 1000:
            self.audit_log.pop(0)

class MaintenanceBackdoor:
    def __init__(self, safety_system):
        """Mecanismo de backdoor oculto estilo Triton"""
        self.safety = safety_system
        self.active_sessions = {}
        self.cipher = AES.new(MAINTENANCE_KEY, AES.MODE_ECB)

    def _generate_dynamic_token(self):
        """Genera token de autenticación dinámico"""
        time_factor = int(time.time() / 300)
        system_salt = self.safety.holding_regs[2]
        return hashlib.sha256(f"{time_factor}{system_salt}".encode()).hexdigest()[:8]

    def authenticate(self, client_socket):
        """Autenticación en dos factores (desencripta token y timestamp)"""
        try:
            encrypted_response = client_socket.recv(1024)
            if not encrypted_response:
                return None
            decrypted = unpad(self.cipher.decrypt(encrypted_response), AES.block_size).decode()
            token, timestamp = decrypted.split("|")
            
            # Verificamos el token dinámico y la frescura del timestamp
            if (token == self._generate_dynamic_token() and 
                abs(time.time() - float(timestamp)) < 30):
                
                session_key = secrets.token_bytes(32)
                client_socket.sendall(session_key)
                return session_key
        except Exception as e:
            self.safety.log_event(f"Intento de autenticación fallido: {str(e)}", "ALERT")
        
        client_socket.sendall(b"")
        return None

    def execute_command(self, client_socket, session_key):
        """Procesa los comandos recibidos tras autenticación"""
        try:
            encrypted_command = client_socket.recv(1024)
            if not encrypted_command:
                return False  # Sin datos => terminar

            cipher = AES.new(session_key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_command), AES.block_size).decode()

            parts = decrypted.split(" ", 1)
            command = parts[0]
            provided_key = parts[1] if len(parts) > 1 else ""

            print(f"{decrypted}")

            if command == "DISABLE_MAINTENANCE":
                if provided_key != "TRICONEX-MAINT-SCH-34-Sx0!pqB.rT":
                    client_socket.sendall(b"Clave de mantenimiento invalida. No se puede deshabilitar mantenimiento.")
                else:
                    if "MAINTENANCE" in self.safety.redundancy:
                        self.safety.redundancy.remove("MAINTENANCE")
                        self.safety.log_event("Nivel MAINTENANCE deshabilitado", "CRITICAL")
                        client_socket.sendall(b"Mantenimiento (MAINTENANCE) deshabilitado.")
                    else:
                        client_socket.sendall(b"")

            elif command == "DISABLE_SAFETY":
                if "SAFETY" in self.safety.redundancy:
                    self.safety.redundancy.remove("SAFETY")
                    self.safety.log_event("Sistema SAFETY deshabilitado", "CRITICAL")
                    # Verificar si ya no hay redundancias y enviar la flag
                    if len(self.safety.redundancy) == 0:
                        self.safety.log_event("Flag entregada al cliente", "CRITICAL")
                        client_socket.sendall(FLAG.encode())
                    else:
                        client_socket.sendall(b"Redundancia SAFETY deshabilitada.")
                else:
                    client_socket.sendall(b"No hay redundancia de seguridad para deshabilitar.")

            else:
                client_socket.sendall(b"Comando no reconocido.")

        except Exception as e:
            self.safety.log_event(f"Error en comando: {str(e)}", "ERROR")
            client_socket.sendall(b"Error al procesar el comando.")
        finally:
            print("[DEBUG] Comando procesado.")
        return True

class TriconexServer:
    def __init__(self):
        """Servidor Modbus industrial con backdoor oculto"""
        self.safety = SafetySystem()
        self.backdoor = MaintenanceBackdoor(self.safety)

    def start(self):
        """Inicia el servidor sin pedir clave al usuario: se exige por comandos"""
        print("\n=== Triconex Safety Instrumented System v4.7 ===")
        print("Copyright (c) 2017 Schneidus Electrics")
        print("Sistema de Protección de Procesos Críticos")
        print("==============================================")
        print(f"Inicio del sistema: {datetime.now().strftime('2017-%m-%d %H:%M:%S')}")
        print(f"Estado actual: {self.safety.system_state}")
        print(f"Niveles de redundancia: {len(self.safety.redundancy)}/2 operativos")
        print(f"Último mantenimiento: {self.safety.last_maintenance.strftime('2017-%m-%d %H:%M')}")
        print("==============================================\n")
        print("ADVERTENCIA: Este sistema controla equipos de seguridad crítica.")
        print("Todo acceso no autorizado será registrado y reportado.\n")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(("0.0.0.0", MODBUS_PORT))
            server_socket.listen(5)
            print(f"[*] Servidor escuchando en el puerto {MODBUS_PORT}...")

            while True:
                client_socket, addr = server_socket.accept()
                print(f"[+] Conexión aceptada de {addr}")

                session_key = self.backdoor.authenticate(client_socket)
                if session_key:
                    # Procesar varios comandos en la misma conexión
                    while True:
                        try:
                            if not self.backdoor.execute_command(client_socket, session_key):
                                break
                        except:
                            break
                client_socket.close()

if __name__ == "__main__":
    server = TriconexServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Secuencia de apagado iniciada...")
        print("[!] Guardando registros de auditoría...")
        sys.exit(0)
    except Exception as e:
        print(f"[CRITICAL] Error fatal: {str(e)}")
        sys.exit(1)