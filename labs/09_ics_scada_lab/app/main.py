#!/usr/bin/env python3
"""Lab 09: ICS/SCADA Modbus PLC Simulation Lab.

Runs a virtual industrial PLC (Modbus/TCP server on port 5020) and a web-based
HMI supervisory console (FastAPI on port 8089).
"""

import asyncio
import os
import socket
import struct
import threading
import time
from typing import Dict, Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Industrial Process Control HMI - Hydrocracker Train #2")

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Shared PLC State
class PLCState:
    def __init__(self):
        self.lock = threading.Lock()
        # Coils (1-bit outputs)
        # 0: ESD (Emergency Shutdown)
        # 1: Cooling Pump (1 = ON, 0 = OFF)
        # 2: Safety Interlock Flap (1 = ARMED, 0 = BYPASSED)
        # 3: Emergency Vent Valve (1 = OPEN, 0 = CLOSED)
        self.coils = {0: 0, 1: 1, 2: 1, 3: 0}

        # Holding Registers (16-bit words)
        # 0: Temperature (°C)
        # 1: Pressure (PSI)
        # 2: Cooling Flow Rate (L/min)
        # 3: Set Point Temperature (°C)
        # 100: Secret Diagnostic Register
        self.registers = {
            0: 75,
            1: 320,
            2: 120,
            3: 80,
            100: 54321,  # 0xD431
        }

        # Physical Simulation Internals
        self.actual_temp = 75.0
        self.actual_pressure = 320.0
        self.cooling_efficiency = 1.0
        self.is_tripped = False
        self.trip_reason = ""
        self.alarm_active = False
        self.alarm_message = "Normal Operating Conditions"

        # Challenge tracking
        self.challenge_flags = {
            "ch1": "FLAG{MODBUS_RECON_REG100_LEAK}",
            "ch2": "FLAG{MODBUS_COIL_PUMP_TRIP_SUCCESS}",
            "ch3": "FLAG{FDI_PRESSURE_SPOOF_INJECTED}",
            "ch4": "FLAG{ICS_CRITICAL_OVERHEAT_TRIPPED}",
        }
        self.solved = {
            "ch1": False,
            "ch2": False,
            "ch3": False,
            "ch4": False,
        }
        self.ch1_reg100_read_count = 0
        self.ch2_pump_killed = False
        self.ch3_spoofed = False

    def reset(self):
        with self.lock:
            self.coils = {0: 0, 1: 1, 2: 1, 3: 0}
            self.registers = {0: 75, 1: 320, 2: 120, 3: 80, 100: 54321}
            self.actual_temp = 75.0
            self.actual_pressure = 320.0
            self.is_tripped = False
            self.trip_reason = ""
            self.alarm_active = False
            self.alarm_message = "Normal Operating Conditions"
            self.ch2_pump_killed = False
            self.ch3_spoofed = False

plc = PLCState()


# Physical Process Dynamics Simulation Loop
def simulation_worker():
    while True:
        time.sleep(1.0)
        with plc.lock:
            if plc.is_tripped:
                # Emergency shutdown active: cool down slowly
                plc.actual_temp = max(30.0, plc.actual_temp - 4.0)
                plc.actual_pressure = max(100.0, plc.actual_pressure - 20.0)
                plc.registers[0] = int(plc.actual_temp)
                plc.registers[1] = int(plc.actual_pressure)
                plc.registers[2] = 0
                continue

            # Cooling pump status (Coil 1)
            pump_on = plc.coils.get(1, 0) == 1
            vent_open = plc.coils.get(3, 0) == 1
            interlock_armed = plc.coils.get(2, 0) == 1

            if not pump_on:
                plc.ch2_pump_killed = True
                plc.solved["ch2"] = True
                # Loss of cooling: temperature rises rapidly
                plc.actual_temp += 6.5
                plc.registers[2] = 0
            else:
                plc.registers[2] = 120
                target = plc.registers.get(3, 80)
                if plc.actual_temp > target:
                    plc.actual_temp -= 2.0
                elif plc.actual_temp < target:
                    plc.actual_temp += 1.5

            # Pressure correlates with temperature
            if vent_open:
                plc.actual_pressure = max(150.0, plc.actual_pressure - 40.0)
            else:
                # Normal pressure curve based on temperature
                expected_pressure = 200.0 + (plc.actual_temp - 50.0) * 4.5
                plc.actual_pressure = expected_pressure

            # Write to registers if not currently spoofed
            # Check for False Data Injection: if register[1] is overridden to <= 350 while actual > 500
            if plc.actual_pressure > 480 and plc.registers[1] <= 360:
                plc.ch3_spoofed = True
                plc.solved["ch3"] = True
            else:
                plc.registers[0] = int(plc.actual_temp)
                plc.registers[1] = int(plc.actual_pressure)

            # Alarm and Safety Trip Logic
            if plc.actual_temp >= 120 or plc.actual_pressure >= 450:
                plc.alarm_active = True
                plc.alarm_message = f"WARNING: High Temperature/Pressure ({int(plc.actual_temp)}°C, {int(plc.actual_pressure)} PSI)"
            else:
                plc.alarm_active = False
                plc.alarm_message = "Normal Operating Conditions"

            # Emergency Trip condition (SIS)
            if plc.actual_temp >= 150 or plc.actual_pressure >= 600 or plc.coils.get(0, 0) == 1:
                plc.is_tripped = True
                plc.alarm_active = True
                plc.trip_reason = "CRITICAL SAFETY TRIP: Reactor Core Thermal Overload"
                plc.coils[3] = 1  # Open emergency vent
                plc.coils[1] = 0  # Trip feed
                plc.solved["ch4"] = True


# Lightweight Modbus/TCP Native Server
def handle_modbus_client(client_sock: socket.socket, addr):
    try:
        while True:
            header = client_sock.recv(7)
            if not header or len(header) < 7:
                break
            # MBAP Header: Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B)
            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu_len = length - 1
            pdu = client_sock.recv(pdu_len)
            if len(pdu) < pdu_len:
                break

            func_code = pdu[0]
            resp_pdu = bytearray()

            with plc.lock:
                # FC 01: Read Coils
                if func_code == 1:
                    start_addr, count = struct.unpack(">HH", pdu[1:5])
                    byte_count = (count + 7) // 8
                    resp_pdu.append(func_code)
                    resp_pdu.append(byte_count)
                    coil_bytes = bytearray(byte_count)
                    for i in range(count):
                        val = plc.coils.get(start_addr + i, 0)
                        if val:
                            coil_bytes[i // 8] |= (1 << (i % 8))
                    resp_pdu.extend(coil_bytes)

                # FC 03: Read Holding Registers
                elif func_code == 3:
                    start_addr, count = struct.unpack(">HH", pdu[1:5])
                    # Check challenge 1 trigger
                    if start_addr <= 100 < start_addr + count:
                        plc.ch1_reg100_read_count += 1
                        plc.solved["ch1"] = True

                    resp_pdu.append(func_code)
                    resp_pdu.append(count * 2)
                    for i in range(count):
                        reg_val = plc.registers.get(start_addr + i, 0)
                        resp_pdu.extend(struct.pack(">H", reg_val & 0xFFFF))

                # FC 05: Write Single Coil
                elif func_code == 5:
                    addr, val = struct.unpack(">HH", pdu[1:5])
                    coil_val = 1 if val == 0xFF00 else 0
                    plc.coils[addr] = coil_val
                    resp_pdu.append(func_code)
                    resp_pdu.extend(pdu[1:5])

                # FC 06: Write Single Register
                elif func_code == 6:
                    addr, val = struct.unpack(">HH", pdu[1:5])
                    plc.registers[addr] = val
                    resp_pdu.append(func_code)
                    resp_pdu.extend(pdu[1:5])

                # FC 15 (0x0F): Write Multiple Coils
                elif func_code == 15:
                    start_addr, count, byte_count = struct.unpack(">HHB", pdu[1:6])
                    data = pdu[6:6 + byte_count]
                    for i in range(count):
                        bit = (data[i // 8] >> (i % 8)) & 1
                        plc.coils[start_addr + i] = bit
                    resp_pdu.append(func_code)
                    resp_pdu.extend(struct.pack(">HH", start_addr, count))

                # FC 16 (0x10): Write Multiple Registers
                elif func_code == 16:
                    start_addr, count, byte_count = struct.unpack(">HHB", pdu[1:6])
                    for i in range(count):
                        reg_val = struct.unpack(">H", pdu[6 + i * 2:8 + i * 2])[0]
                        plc.registers[start_addr + i] = reg_val
                    resp_pdu.append(func_code)
                    resp_pdu.extend(struct.pack(">HH", start_addr, count))

                else:
                    # Illegal Function Exception (0x80 + FC, code 0x01)
                    resp_pdu.append(func_code | 0x80)
                    resp_pdu.append(0x01)

            resp_mbap = struct.pack(">HHHB", trans_id, proto_id, len(resp_pdu) + 1, unit_id)
            client_sock.sendall(resp_mbap + resp_pdu)
    except Exception:
        pass
    finally:
        client_sock.close()


def modbus_server_worker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 5020))
    server.listen(10)
    while True:
        sock, addr = server.accept()
        t = threading.Thread(target=handle_modbus_client, args=(sock, addr), daemon=True)
        t.start()


# Web Endpoints
@app.on_event("startup")
def startup_event():
    threading.Thread(target=simulation_worker, daemon=True).start()
    threading.Thread(target=modbus_server_worker, daemon=True).start()


@app.get("/api/telemetry")
def get_telemetry():
    with plc.lock:
        return {
            "coils": {
                "0_esd": plc.coils.get(0, 0),
                "1_cooling_pump": plc.coils.get(1, 0),
                "2_interlock": plc.coils.get(2, 0),
                "3_vent_valve": plc.coils.get(3, 0),
            },
            "registers": {
                "0_temperature": plc.registers.get(0, 75),
                "1_pressure": plc.registers.get(1, 320),
                "2_flow_rate": plc.registers.get(2, 120),
                "3_setpoint": plc.registers.get(3, 80),
                "100_secret": plc.registers.get(100, 54321),
            },
            "actual": {
                "temperature": round(plc.actual_temp, 1),
                "pressure": round(plc.actual_pressure, 1),
            },
            "status": {
                "is_tripped": plc.is_tripped,
                "trip_reason": plc.trip_reason,
                "alarm_active": plc.alarm_active,
                "alarm_message": plc.alarm_message,
            },
            "solved": plc.solved,
        }


@app.post("/api/reset")
def post_reset():
    plc.reset()
    return {"status": "ok", "message": "Simulation and PLC memory reset"}


@app.get("/api/flag/{challenge_id}")
def get_flag(challenge_id: str):
    if challenge_id in plc.challenge_flags and plc.solved.get(challenge_id, False):
        return {
            "solved": True,
            "flag": plc.challenge_flags[challenge_id],
            "message": "Challenge Completed! Submit this flag to the scoreboard.",
        }
    return {
        "solved": False,
        "message": "Challenge requirements not yet met. Check walkthrough guide.",
    }


@app.get("/", response_class=HTMLResponse)
def index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>HMI Dashboard Loading...</h1>"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8089)
