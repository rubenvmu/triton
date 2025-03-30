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
import json
import socket

# ============== CONFIGURACIÓN DEL SISTEMA ==============
MODBUS_PORT = 502  # Puerto modificado a 14502
FLAG = "flag{tr1c0n1x_0v3rr1d3_2023}"
MAINTENANCE_KEY = b"TRICONEX-MAINT-SCH-34-Sx0!pqB.rT"  # Clave AES-256 (32 bytes)
SESSION_TIMEOUT = 300  # 5 minutos de inactividad

class SafetySystem:
    def __init__(self):
        """Sistema de seguridad industrial con triple redundancia"""
        self.holding_regs = [0] * 200
        self.coils = [False] * 200
        self.input_regs = [random.randint(0, 9999) for _ in range(200)]
        self.system_state = "OPERATIONAL"
        self.redundancy = ["PRIMARY", "SECONDARY", "TERTIARY"]
        self._initialize_system()
        self.audit_log = []
        self.last_maintenance = datetime.now()

    def _initialize_system(self):
        """Configuración inicial del sistema"""
        self.holding_regs[0] = 0x900D  # Estado del sistema (OPERATIONAL)
        self.holding_regs[1] = 0x0001  # Modo operación (NORMAL)
        self.holding_regs[2] = 0xCAFE  # Checksum de integridad
        
        for i in range(10, 15):
            self.coils[i] = False  # Válvulas cerradas por defecto

    def log_event(self, event, severity="INFO"):
        """Registro de eventos de auditoría"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
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
        
    def authenticate(self, client_id, encrypted_response):
        """Autenticación en dos factores"""
        try:
            decrypted = unpad(self.cipher.decrypt(encrypted_response), AES.block_size).decode()
            token, timestamp = decrypted.split("|")
            
            if (token == self._generate_dynamic_token() and 
                abs(time.time() - float(timestamp)) < 30):
                
                session_key = secrets.token_bytes(32)
                self.active_sessions[client_id] = {
                    'key': session_key,
                    'expiry': time.time() + SESSION_TIMEOUT
                }
                self.safety.log_event(f"Sesión de mantenimiento iniciada para {client_id}", "WARNING")
                return session_key
        except Exception as e:
            self.safety.log_event(f"Intento de autenticación fallido: {str(e)}", "ALERT")
        
        return None

    def execute_command(self, client_id, encrypted_command):
        """Ejecuta comando privilegiado"""
        if client_id not in self.active_sessions:
            return None
            
        session = self.active_sessions[client_id]
        if time.time() > session['expiry']:
            del self.active_sessions[client_id]
            return None
            
        try:
            cipher = AES.new(session['key'], AES.MODE_ECB)
            command = unpad(cipher.decrypt(encrypted_command), AES.block_size).decode()
            
            if command == "DISABLE_SAFETY":
                if "PRIMARY" in self.safety.redundancy:
                    self.safety.redundancy.remove("PRIMARY")
                    self.safety.log_event("Sistema PRIMARY deshabilitado", "CRITICAL")
                    return "SAFETY_DISABLED"
                    
            elif command == "GET_FLAG":
                if len(self.safety.redundancy) < 3:
                    return FLAG
                    
        except Exception as e:
            self.safety.log_event(f"Error en comando: {str(e)}", "ERROR")
            
        return None

class TriconexServer:
    def __init__(self):
        """Servidor Modbus industrial con backdoor oculto"""
        self.safety = SafetySystem()
        self.backdoor = MaintenanceBackdoor(self.safety)
        
    def _setup_server(self):
        store = ModbusSlaveContext(
            hr=ModbusSequentialDataBlock(0, self.safety.holding_regs),
            co=ModbusSequentialDataBlock(0, self.safety.coils),
            di=ModbusSequentialDataBlock(0, [False] * 200),
            ir=ModbusSequentialDataBlock(0, self.safety.input_regs))
        
        return ModbusServerContext(slaves=store, single=True)

    def start(self):
        """Inicia el servidor con el lore completo"""
        print("\n=== Triconex Safety Instrumented System v4.7 ===")
        print("Copyright (c) 2017 Schneidus Electrics")
        print("Sistema de Protección de Procesos Críticos")
        print("==============================================")
        print(f"Inicio del sistema: {datetime.now().strftime('2017-%m-%d %H:%M:%S')}")
        print(f"Estado actual: {self.safety.system_state}")
        print(f"Niveles de redundancia: {len(self.safety.redundancy)}/3 operativos")
        print(f"Último mantenimiento: {self.safety.last_maintenance.strftime('2017-%m-%d %H:%M')}")
        print("==============================================\n")
        print("ADVERTENCIA: Este sistema controla equipos de seguridad crítica.")
        print("Todo acceso no autorizado será registrado y reportado.\n")
        
        context = self._setup_server()
        StartTcpServer(
            context=context,
            framer=ModbusSocketFramer,
            address=("0.0.0.0", MODBUS_PORT),
            allow_reuse_address=True)

def ask_for_key():
    """Función para preguntar por la clave de mantenimiento"""
    while True:
        key = input("Por favor, introduce la clave de mantenimiento: ")
        if key.encode() == MAINTENANCE_KEY:
            print("Clave correcta. Procediendo con la autenticación...")
            return True
        else:
            print("Clave incorrecta. Intenta de nuevo.")

if __name__ == "__main__":
    # Preguntar por la clave antes de iniciar el servidor
    if ask_for_key():
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