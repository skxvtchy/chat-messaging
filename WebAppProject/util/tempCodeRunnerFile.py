small = generate_ws_frame(b"Hello, WebSocket!")
print("Small Payload Frame:", small)

# Large Frame
large = generate_ws_frame(b"a" * 70000)  # Larger than 65535 bytes
print("Large Payload Frame:", large[:10], "...") 