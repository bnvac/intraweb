# Pocket access point (ESP32)

No router? An ESP32 board (about $5) becomes the Wi-Fi network instead.

1. Open `esp32-ap.ino` and set `NETWORK_NAME` and `PASSWORD`.
2. Flash it, board **ESP32 Dev Module**:

   ```sh
   arduino-cli compile --fqbn esp32:esp32:esp32 hardware/esp32-ap
   arduino-cli upload  --fqbn esp32:esp32:esp32 -p /dev/ttyUSB0 hardware/esp32-ap
   ```

3. Power it from any USB port or battery bank. Join the network, run
   `intraweb up`, and neighbors appear as on any other Wi-Fi.

What it does and does not do:

- It is only a radio. It gives out addresses (10.42.0.x) and forwards traffic
  between the machines on it. It stores nothing and relays no one's content,
  so the rule that a hub never proxies holds here too.
- It does not isolate clients and keeps power saving off, so both discovery
  paths work: mDNS and the broadcast beacon.
- There is no internet behind it. Every DNS name points at the board, so a
  phone that joins shows a page explaining what this network is and what to
  run.
- An ESP32 takes at most 10 devices, and throughput is a few megabits: right
  for a table of laptops and a field kit, too small for a room. For more
  people, any old router with no internet cable works, with client isolation
  switched off.
