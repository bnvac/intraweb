// intraweb pocket access point.
//
// Turns an ESP32 into a Wi-Fi network for places with no router: a field site,
// a classroom, a power cut. Laptops and Pis join it and run `intraweb up` as
// usual; discovery, pages, mail and files all work peer to peer over it.
//
// The ESP32 is only the radio. It hands out addresses and forwards frames
// between the machines on it. It never stores, proxies or relays anyone's
// content, so it is not a hub and cannot become one.
//
// Build with the Arduino IDE or arduino-cli, board "ESP32 Dev Module"
// (arduino-esp32 2.x or 3.x). No extra libraries.

#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>

// Change these two before flashing. A password keeps passers-by off the air;
// it is not what keeps private channels private -- those are encrypted
// end to end whatever the network.
static const char *NETWORK_NAME = "intraweb";
static const char *PASSWORD = "neighborhood"; // 8+ characters, or "" for open

static const uint8_t CHANNEL = 6;
// The ESP32's soft AP tops out at 10 stations. Plenty for a table of laptops;
// for a room, use a real access point with client isolation turned off.
static const uint8_t MAX_CLIENTS = 10;

static const IPAddress AP_IP(10, 42, 0, 1);
static const IPAddress NETMASK(255, 255, 255, 0);

DNSServer dns;
WebServer web(80);

// There is no internet behind this radio, so every name resolves here and
// phones show this page as a "sign in to network" sheet. That is the moment
// someone needs to be told what this network is and what to run.
// .local names (intranet.local) are answered by the hub over mDNS, not by
// this DNS, so the hub's own address keeps working.
static const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>intraweb</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:34em;margin:2em auto;padding:0 1em;color:#111}
h1{margin:0;font-size:1.8em}p.s{margin:.2em 0 1.4em;color:#555}
code{background:#eef1f7;padding:.1em .35em;border-radius:3px}
li{margin:.4em 0}small{color:#777}</style></head><body>
<h1>intraweb</h1><p class="s">your neighborhood web &middot; no internet here, on purpose</p>
<p>This network is a radio and nothing else. Everyone on it can see each other's pages, send signed mail and swap files directly.</p>
<ol><li>Install intraweb on a laptop or Pi.</li>
<li>Run <code>intraweb up</code>.</li>
<li>Open <a href="http://intranet.local">intranet.local</a> if someone is running a hub, or <code>http://localhost:8420</code> on your own machine.</li></ol>
<p><small>%CLIENTS% connected &middot; up %UPTIME% min</small></p>
</body></html>)HTML";

void servePage() {
  String page = FPSTR(PAGE);
  page.replace("%CLIENTS%", String(WiFi.softAPgetStationNum()));
  page.replace("%UPTIME%", String(millis() / 60000));
  web.send(200, "text/html; charset=utf-8", page);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  // Power saving delays broadcast frames, and the discovery beacon is a
  // broadcast. Keep the radio awake.
  WiFi.setSleep(false);
  WiFi.softAPConfig(AP_IP, AP_IP, NETMASK);
  bool ok = WiFi.softAP(NETWORK_NAME, strlen(PASSWORD) ? PASSWORD : nullptr,
                        CHANNEL, 0, MAX_CLIENTS);
  if (!ok) {
    Serial.println("Could not start the access point. A password must be at "
                   "least 8 characters, or empty for an open network.");
    return;
  }
  dns.setErrorReplyCode(DNSReplyCode::NoError);
  dns.start(53, "*", AP_IP);
  web.onNotFound(servePage);
  web.on("/", servePage);
  web.begin();
  Serial.printf("intraweb network \"%s\" is up at %s\n", NETWORK_NAME,
                AP_IP.toString().c_str());
}

void loop() {
  dns.processNextRequest();
  web.handleClient();
}
