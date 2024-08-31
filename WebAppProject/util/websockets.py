import base64
import hashlib

def compute_accept(web_key):
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    combined = web_key + GUID
    sha1_result = hashlib.sha1(combined.encode()).digest()
    accept = base64.b64encode(sha1_result).decode('utf-8')
    return accept

def parse_ws_frame(ws_bytes):
    class WebSocket:
        def __init__(self, fin_bit, opcode, payload_length, payload):
            self.fin_bit = fin_bit
            self.opcode = opcode
            self.payload_length = payload_length
            self.payload = payload

    first, second = ws_bytes[0], ws_bytes[1]

    mbit = (second >> 7) & 0x01
    payload_length = second & 0x7F
    fin_bit = (first >> 7) & 0x01
    opcode = first & 0x0F
    
    # check payload length
    start = 2

    if payload_length == 126:
        start = 4
        payload_length = int.from_bytes(ws_bytes[2:4], byteorder='big')
    elif payload_length == 127:
        start = 10
        payload_length = int.from_bytes(ws_bytes[2:10], byteorder='big')

    # check bit
    payload = bytearray()
    
    if mbit == 0x01:
        mask = ws_bytes[start:start + 4]
        start += 4
        for i in range(start, start + payload_length):
            mask_idx = (i - start) % 4
            xor = ws_bytes[i] ^ mask[mask_idx]
            payload.append(xor)
    else:
        payload = ws_bytes[start:start + payload_length]

    return WebSocket(fin_bit, opcode, payload_length, payload)


def generate_ws_frame(pay_bytes):
   
    fin_bit = 0x80
    opcode = 0x0001

    fin_opcode = fin_bit | opcode
    frame = bytearray([fin_opcode])

    payload_length = len(pay_bytes)
    

    if payload_length <= 125:
        length = len(pay_bytes)
        frame.append(length)
    elif payload_length <= 65535:
        frame.append(126)
        length = len(pay_bytes).to_bytes(2, 'big')
        frame.extend(length)
     
    else:
        frame.append(127)
        length = len(pay_bytes).to_bytes(8, 'big')
        frame.extend(length)

    # extend that shit
    frame.extend(pay_bytes)
    
    return bytes(frame)



# # Payload
# frame_data = b'\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58'
# parsed = parse_ws_frame(frame_data)
# print(f"FIN bit: {parsed.fin_bit}, Opcode: {parsed.opcode}, Payload: {parsed.payload}")

# # Small Frame
# small = generate_ws_frame(b"Hello, WebSocket!")
# print("Small Payload Frame:", small)

# # Large Frame
# large = generate_ws_frame(b"a" * 70000)  # Larger than 65535 bytes
# print("Large Payload Frame:", large[:10], "...") 
