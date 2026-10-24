// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/sockets.h>   // DNS engine talks to plain UDP sockets
#include <freertos/semphr.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch

// Embedded Mozilla root CA bundle (lives in ESP-IDF prebuilt libmbedtls.a as an
// asm blob). Passed to WiFiClientSecure::setCACertBundle() so https:// URLs
// verify against real public CAs instead of accepting arbitrary forged certs
// (the old setInsecure() scheme) or failing the handshake unconditionally.
extern "C" const uint8_t x509_crt_bundle[];
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
// Compile-time defaults for the upstream resolver. Both can be changed at
// runtime from the dashboard (上游 DNS panel) and persist to /upstream.cfg.
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress DEFAULT_UPSTREAM(UPSTREAM_IP);
static const uint16_t DEFAULT_UPSTREAM_PORT = UPSTREAM_PORT;
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
// 744h = 31 days. Bounds the interval so updateIntervalH * 3600000 can't overflow
// 32 bits, and keeps it under millis()' ~49-day rollover so elapsed-time
// comparisons stay correct across a wrap.
static const uint32_t MAX_UPDATE_INTERVAL_H = 744;
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// runtime-configurable upstream resolver (defaults above; the dashboard's
// 上游 DNS panel changes them via /setupstream, persisted to /upstream.cfg;
// the DNS task reads them for every send, so changes apply on the fly)
IPAddress upstreamIp = DEFAULT_UPSTREAM;
uint16_t upstreamPort = DEFAULT_UPSTREAM_PORT;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// Runtime-changeable dashboard login (/setcreds endpoint: user + pass + OTA).
//
// secrets.h declares WEB_USER/WEB_PASS/OTA_PASS as `static const char*` —
// pointer to const, not const pointer — so the pointer itself is assignable.
// loadAuth() just retargets them at long-lived buffers and every existing call
// site (web.authenticate in requireAuth/handleStats/the two upload handlers,
// and ArduinoOTA.setPassword) picks up the new value with no further change.
//
// WEB_PASS and OTA_PASS are now independent — you can change the dashboard
// password without touching OTA, or vice versa. This matches the existing
// pattern where secrets.example.h sets them equal but they're separate strings.
//
// /setcreds requires Basic Auth (like every mutating endpoint) — the browser
// will pop its own login prompt if the cached credentials are stale or
// missing, which is exactly the same behavior as /ban, /addblock, etc.
//
// NVS namespace "auth" is separate from "wifi", so /forgetwifi doesn't touch
// the login — but the BOOT tap-tap-hold gesture wipes both, so a board that
// has been locked out of its own dashboard still has a way back.
String authUserBuf, authPassBuf, authOtaBuf;
static void loadAuth() {
  prefs.begin("auth", true);
  String u = prefs.getString("user", "");
  String p = prefs.getString("pass", "");
  String o = prefs.getString("ota", "");
  prefs.end();
  if (u.length()) { authUserBuf = u; WEB_USER = authUserBuf.c_str(); }
  if (p.length()) { authPassBuf = p; WEB_PASS = authPassBuf.c_str(); }
  if (o.length()) { authOtaBuf = o; OTA_PASS = authOtaBuf.c_str(); }
}

// ---- BOOT-button + on-board LED ----
// BOOT on the C3 is GPIO9, the boot-mode strapping pin, and it doubles as the
// factory-reset input while the app runs. It is a cheap tactile switch on a
// bare GPIO with no external cap, so both edges bounce for several ms — and a
// false "press" here means wiping the operator's credentials, so the input is
// debounced by stability (a level only counts once it has held for
// BOOT_DEBOUNCE), not by rejecting edges inside a fixed window.
#if CONFIG_IDF_TARGET_ESP32C3
static const int BOOT_PIN = 9;      // C3 BOOT button (also the boot-mode strapping pin)
#else
static const int BOOT_PIN = 0;      // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
static const uint32_t BOOT_DEBOUNCE = 50;      // a level must hold this long to count
static const uint32_t BOOT_TAP_GAP  = 600;     // max ms between gesture presses
static const uint32_t BOOT_HOLD_MS  = 1700;    // 3rd press must be held this long
static const uint32_t BOOT_ARM_WIN  = 10000;   // stay armed this long waiting for confirm

// A stable reading plus exactly-once press/release events. Returns true when
// `pressed` has just been seen held; `*released` when it has just been seen let
// go. Both settle BOOT_DEBOUNCE ms after the raw level last changed.
static bool bootBtnStable = true;   // debounced: true = released (INPUT_PULLUP is active-low)
static bool bootBtnRaw    = true;
static uint32_t bootBtnRawT = 0;
static bool bootBtnStep(uint32_t now, bool* released) {
  bool raw = digitalRead(BOOT_PIN) == LOW;
  *released = false;
  if (raw != bootBtnRaw) { bootBtnRaw = raw; bootBtnRawT = now; return false; }
  if (raw == bootBtnStable || now - bootBtnRawT < BOOT_DEBOUNCE) return false;
  bootBtnStable = raw;
  if (raw) return true;
  *released = true;
  return false;
}

// ---- on-board LED (factory-reset handshake indicator) ----
// Board is an ESP32-C3 Super Mini: the built-in LED is a plain blue LED on
// GPIO8 with inverted logic — LOW lights it, HIGH turns it off (the common
// "reverse" design). NOT a WS2812, so no neopixelWrite/RMT. A plain
// digitalWrite level is stable and needs no frame-reassertion machinery: once
// written HIGH it stays dark until the handshake writes LOW again.
#if CONFIG_IDF_TARGET_ESP32C3
static const int LED_PIN = 8;      // Super Mini on-board LED, active-low
#else
static const int LED_PIN = 2;      // classic ESP32 on-board LED, active-low too
#endif
static void ledWrite(bool on) { digitalWrite(LED_PIN, on ? LOW : HIGH); }
static void ledInit() {
  pinMode(LED_PIN, OUTPUT);
  ledWrite(true); delay(80);       // boot blink: confirms the LED works
  ledWrite(false);                 // then park it off
}

// ---- BOOT-button factory-reset handshake ----
// Why not "hold BOOT at power-on" (the upstream pattern): on the C3, BOOT is
// GPIO9, the boot-mode strapping pin, sampled by the ROM only at reset
// release — LOW there means "enter serial download mode", so the app never
// runs. Holding BOOT across a reset therefore lands in the bootloader, not in
// this code, and with the board already running there is no reset event to
// sample. "BOOT held at boot" was structurally dead code.
//
// The replacement gesture runs entirely while the app is up, when GPIO9 is
// just a readable input:
//   1. tap, tap, then press-and-hold (>2 s) — three presses total
//   2. on success the blue LED goes solid: the wipe is ARMED, nothing erased yet
//   3. press BOOT once more while lit -> wipe NVS ("wifi" + "auth") + reboot
//   4. press nothing for 10 s -> LED off, disarmed
// Three presses plus a deliberate confirm makes accidental triggers from a
// knock or a cable tug essentially impossible; the wipe is never the first
// reaction to any single press.
enum BootGest { BG_IDLE, BG_TAPS, BG_HELD, BG_ARMED };
BootGest bootGest = BG_IDLE;
uint32_t bootGestT = 0;        // when the current state/step began
uint32_t bootTaps = 0;         // presses counted toward the gesture

static void bootDisarm(const char* why) {
  bootGest = BG_IDLE; bootTaps = 0; ledWrite(false);
  if (why) Serial.println(why);
}
static void wipeCredsAndReboot() {
  Serial.println("[reset] BOOT handshake confirmed: wiping WiFi + credentials, rebooting");
  prefs.begin("wifi", false); prefs.clear(); prefs.end();
  prefs.begin("auth", false); prefs.clear(); prefs.end();
  ledWrite(false);
  delay(200);
  ESP.restart();
}
static void bootGestStep() {
  uint32_t now = millis();
  bool released;
  bool pressed = bootBtnStep(now, &released);

  switch (bootGest) {
    case BG_IDLE:
      if (pressed) { bootTaps = 1; bootGestT = now; bootGest = BG_TAPS; }
      break;
    case BG_TAPS:
      if (pressed) {
        // a slow single press just restarts the count; only presses that follow
        // each other inside the gap accumulate into the gesture
        bootTaps = (now - bootGestT <= BOOT_TAP_GAP) ? bootTaps + 1 : 1;
        bootGestT = now;
        if (bootTaps >= 3) bootGest = BG_HELD;    // 3rd press: now it must be held
      } else if (now - bootGestT > BOOT_TAP_GAP) {
        bootDisarm(nullptr);                       // gesture stalled out
      }
      break;
    case BG_HELD:
      if (released) bootDisarm("[reset] aborted (released too early)");
      else if (now - bootGestT >= BOOT_HOLD_MS) {
        bootGest = BG_ARMED; bootGestT = now; ledWrite(true);
        Serial.println("[reset] armed — press BOOT once more to wipe, or wait 10s");
      }
      break;
    case BG_ARMED:
      if (pressed) wipeCredsAndReboot();           // confirmed
      else if (now - bootGestT > BOOT_ARM_WIN) {
        bootDisarm("[reset] disarmed (timed out)");
      }
      break;
  }
}

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
// The DNS task and loop() (web handlers, OTA, remote fetch) share the blocklist file handle, its
// index/verdict cache and the custom-domain list. This one mutex guards all of them; hold it only
// around the in-memory work, never across flash writes or network I/O.
static SemaphoreHandle_t listMux;
struct ListLock { ListLock() { xSemaphoreTake(listMux, portMAX_DELAY); } ~ListLock() { xSemaphoreGive(listMux); } };
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  // Drop cached verdicts first and unconditionally: they describe the previous list, and an
  // empty/missing new list returns early below (it used to skip the clear, so isBlockedHash()
  // kept serving stale "blocked" answers for a list that no longer existed).
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  ListLock lk;
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// Canonical form of a user-supplied domain: what tools/build_blocklist.py's norm() and
// parseQuery() produce (lower-case, no leading "*." / ".", no trailing ".", no "www."), so an
// entry hashes exactly like the queries it is meant to catch. Returns "" when the text can't be
// a hostname (a pasted URL, spaces, non-ASCII ...): such entries used to be stored and then
// silently never matched anything.
static String normDomain(String d) {
  d.trim(); d.toLowerCase();
  while (d.startsWith("*")) d.remove(0, 1);
  while (d.startsWith(".")) d.remove(0, 1);
  while (d.endsWith(".")) d.remove(d.length() - 1);
  if (d.startsWith("www.")) d.remove(0, 4);
  if (d.length() > 253 || d.indexOf('.') < 1 || d.indexOf("..") >= 0) return "";
  for (size_t i = 0; i < d.length(); i++) {
    const char c = d[i];
    if (!(isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.')) return "";
  }
  return d;
}
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = normDomain(f.readStringUntil('\n'));
    bool dup = false;
    for (int i = 0; i < numCustom; i++) if (customDom[i] == l) { dup = true; break; }
    if (l.length() && !dup) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d = normDomain(d);
  if (!d.length() || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  { ListLock lk; customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; }
  saveCustom(); return true;
}
static void removeCustom(String d) {
  d = normDomain(d);
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    { ListLock lk; for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; } numCustom--; }
    saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
// bannedIP[] is the source of truth (it survives reboots and a full client
// table); Dev.banned is only a display mirror. Mutate the array directly and
// persist it verbatim — rebuilding it from clients[] used to silently drop
// bans for IPs that hadn't sent a DNS query since boot.
// Returns false only when a ban could not be recorded because the table is full.
static bool setBan(uint32_t ip, bool on) {
  bool have = false;
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) {
    have = true;
    if (!on) { for (int j = i; j < numBanned - 1; j++) bannedIP[j] = bannedIP[j + 1]; numBanned--; }
    break;
  }
  if (on && !have && numBanned < MAX_BAN) bannedIP[numBanned++] = ip;
  // Mirror what is actually enforced, not what was asked for: with a full table the row used to
  // show "已封禁" although dnsQuery() (which reads bannedIP[]) kept answering that client.
  const bool now = isBannedIP(ip);
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) clients[i].banned = now;
  return !on || now;
}
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static bool macUnknown(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return false; return true; }
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    clients[i].lastSeen = millis();
    // The ARP entry often doesn't exist yet on a client's very first query (e.g. right after a
    // reboot, when clients still have us cached and never ARP). Without this retry such a row
    // stayed 00:00:00:00:00:00 for as long as it lived in the table.
    if (macUnknown(clients[i].mac)) getMac(ip, clients[i].mac);
    return &clients[i];
  }
  // New row, or — table full — recycle the least-recently-seen one. Ban state lives in bannedIP[],
  // never in this table, so an eviction can't drop a ban (see setBan()).
  Dev* c = &clients[0];
  if (numClients < MAX_CLIENTS) c = &clients[numClients];
  else for (int i = 1; i < numClients; i++) if ((int32_t)(clients[i].lastSeen - c->lastSeen) < 0) c = &clients[i];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip);
  getMac(ip, c->mac);
  if (c == &clients[numClients]) numClients++;   // publish the row only once it is filled in (the web side reads it concurrently)
  return c;
}

// ---------- DNS ----------
// A dedicated task owns both UDP sockets, so DNS keeps flowing while loop() is busy with the web
// UI, an upload, OTA, flash writes or a TLS download. Every query that is not blocked sits in a
// small pending table: it is re-sent when the upstream has not answered, and if the upstream stays
// silent the client gets SERVFAIL after PEND_FAIL_MS. (The old code forwarded one query at a time,
// blocking everything for up to a second, then dropped it without a word — clients sat out their own
// multi-second timeout, which looks like "sometimes slow" and Android's "no internet" check.)
// ===== DNS ENGINE BEGIN
static const int PEND_MAX = 32;                  // queries waiting for an upstream answer
static const int PEND_QMAX = 350;                // longest query handled (legal ones stay under ~330 B)
static const int DNS_TASK_PRIO = 19;             // just above lwIP's tcpip thread (18): see dnsStart()
static const uint32_t PEND_RETRY_MS = 400;       // re-send if the upstream has not answered yet
static const uint32_t PEND_FAIL_MS = 1200;       // give up: SERVFAIL (sends happen at 0 / 400 / 800 ms)

struct Pend {
  uint32_t cip, t0, ts;                          // client IP; first and last send (ms)
  uint16_t cport, qlen, qend, cid, wid;          // client port; query / question length; client / upstream txid
  uint8_t tries;                                 // sends so far (0 = slot free)
  uint8_t* q;                                    // malloc'd copy of the query exactly as sent upstream (txid = wid)
};
static Pend pend[PEND_MAX];
static int dnsFd = -1, upFd = -1;
static uint32_t dnsRetry = 0, dnsFail = 0;       // shown in /stats.json
static TaskHandle_t dnsTaskH;

static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;                                  // no compression pointers in a question
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
// Turn the query in buf into a reply (flags 0x8180 | rcode, no records) — except an A query with
// a == true, which gets one 0.0.0.0 record. Returns the reply length.
static int mkReply(int qend, uint8_t rcode, bool a) {
  buf[2] = 0x81; buf[3] = 0x80 | rcode; memset(buf + 6, 0, 6); buf[7] = a;
  if (!a) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static void sendTo(int fd, uint32_t ip, uint16_t port, const void* p, int n) {
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_addr.s_addr = ip; a.sin_port = htons(port);
  sendto(fd, p, n, 0, (sockaddr*)&a, sizeof(a));
}
static void pendSend(Pend& p) {                  // (re)send to the *current* upstream (the dashboard can change it)
  p.tries++; p.ts = millis();
  sendTo(upFd, (uint32_t)upstreamIp, upstreamPort, p.q, p.qlen);
}
static void pendDone(Pend& p) { free(p.q); p.q = nullptr; p.tries = 0; }
static void servfail(const uint8_t* q, int qend, uint32_t cip, uint16_t cport, uint16_t cid) {
  dnsFail++;                                     // count first: the client may see the reply before this task runs again
  if (q != buf) memcpy(buf, q, qend);
  buf[0] = cid >> 8; buf[1] = cid;
  sendTo(dnsFd, cip, cport, buf, mkReply(qend, 2, false));
}
// One client datagram (qlen bytes) is in buf.
static void dnsQuery(uint32_t cip, uint16_t cport, int qlen) {
  if (qlen < 13 || qlen > PEND_QMAX || (buf[2] & 0x80)) return;   // runt, absurdly long, or a *response* (QR=1): a resolver never answers those
  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  Dev* c = getClient(cip);
  // bannedIP[] is the source of truth, not clients[]: a banned IP evicted from / absent out of the
  // 96-slot table must still be blocked
  if (isBannedIP(cip) || (blockingOn && dl && isBlocked(domain))) {
    totalBlocked++; if (c) c->blocked++;
    sendTo(dnsFd, cip, cport, buf, mkReply(qend, 0, qtype == 1));
    return;
  }
  totalAllowed++; if (c) c->allowed++;
  const uint16_t cid = (buf[0] << 8) | buf[1];
  Pend* p = pend;
  while (p < pend + PEND_MAX && p->tries) p++;
  uint8_t* copy = p == pend + PEND_MAX ? nullptr : (uint8_t*)malloc(qlen);
  if (!copy) { servfail(buf, qend, cip, cport, cid); return; }   // table full (or out of memory): fail fast, don't go silent
  p->q = copy; p->cip = cip; p->cport = cport; p->qlen = qlen; p->qend = qend; p->cid = cid; p->t0 = millis();
  for (bool dup = true; dup;) {                  // fresh random txid, unique among the queries in flight
    p->wid = (uint16_t)esp_random(); dup = false;
    for (const Pend& o : pend) if (o.tries && o.wid == p->wid) dup = true;
  }
  memcpy(copy, buf, qlen); copy[0] = p->wid >> 8; copy[1] = p->wid & 0xFF;
  pendSend(*p);
}
// Match an upstream datagram to the query it answers — same txid, same question section, sent by
// the upstream itself — and hand it to the client under the client's own txid. Anything else
// (late duplicates, stray or forged packets) is dropped. Returns false when nothing was waiting.
static bool dnsReply() {
  sockaddr_in from; socklen_t fl = sizeof(from);
  const int n = recvfrom(upFd, buf, sizeof(buf), MSG_DONTWAIT, (sockaddr*)&from, &fl);
  if (n < 0) return false;
  if (n < 12 || n >= (int)sizeof(buf) || from.sin_addr.s_addr != (uint32_t)upstreamIp || ntohs(from.sin_port) != upstreamPort) return true;
  const uint16_t id = (buf[0] << 8) | buf[1];
  for (Pend& p : pend) {
    if (!p.tries || p.wid != id) continue;
    if (n < p.qend || memcmp(buf + 12, p.q + 12, p.qend - 12) != 0) break;
    buf[0] = p.cid >> 8; buf[1] = p.cid & 0xFF;
    sendTo(dnsFd, p.cip, p.cport, buf, n);
    pendDone(p);
    break;
  }
  return true;
}
static bool dnsRecv() {
  sockaddr_in from; socklen_t fl = sizeof(from);
  const int n = recvfrom(dnsFd, buf, sizeof(buf), MSG_DONTWAIT, (sockaddr*)&from, &fl);
  if (n < 0) return false;
  dnsQuery(from.sin_addr.s_addr, ntohs(from.sin_port), n);
  return true;
}
static void dnsSweep() {                         // retries and timeouts
  const uint32_t now = millis();
  for (Pend& p : pend) {
    if (!p.tries) continue;
    if (now - p.t0 >= PEND_FAIL_MS) { servfail(p.q, p.qend, p.cip, p.cport, p.cid); pendDone(p); }
    else if (p.tries < 3 && now - p.ts >= PEND_RETRY_MS) { dnsRetry++; pendSend(p); }
  }
}
static void dnsTask(void*) {
  for (;;) {
    fd_set rs; FD_ZERO(&rs); FD_SET(dnsFd, &rs); FD_SET(upFd, &rs);
    struct timeval tv = {0, 100000};             // sleeps until a datagram arrives; 100 ms is the retry/timeout tick
    const int r = select((dnsFd > upFd ? dnsFd : upFd) + 1, &rs, nullptr, nullptr, &tv);
    bool got = false;
    for (int k = 0; k < 32 && dnsReply(); k++) got = true;   // answers first: they free pending slots
    for (int k = 0; k < 16 && dnsRecv(); k++) got = true;    // capped so the sweep below still runs under a flood
    dnsSweep();
    if (r && !got) vTaskDelay(pdMS_TO_TICKS(10));            // select() failed or reported an error: never spin
  }
}
static void dnsStart() {
  dnsFd = socket(AF_INET, SOCK_DGRAM, 0); upFd = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(DNS_PORT);
  if (dnsFd < 0 || upFd < 0 || bind(dnsFd, (sockaddr*)&a, sizeof(a)) < 0) { Serial.println("DNS socket FAILED"); return; }
  // Priority matters: lwIP's tcpip thread (18) hands datagrams to a socket mailbox that holds only
  // 6 (CONFIG_LWIP_UDP_RECVMBOX_SIZE) and is not compiled in here to change. A task *below* it only
  // runs once the thread has gone idle, so a burst of 7+ queries (browsers and Android fire dozens at
  // once) lost everything past the sixth. At 19 this task takes each datagram the moment it lands.
  xTaskCreate(dnsTask, "dns", 6144, nullptr, DNS_TASK_PRIO, &dnsTaskH);
}
// ===== DNS ENGINE END

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
// Mask a MAC for the unauthenticated /stats.json view: keep the OUI (vendor
// prefix, useful for rough device identification) and zero the last 3 octets.
// A full MAC is a stable device fingerprint; the dashboard only needs it to
// tell clients apart, which aa:bb:cc:00:00:00 does just as well.
static String macMasked(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:00:00:00", m[0],m[1],m[2]); return String(s); }
// JSON string escaping. Control characters (e.g. a "\n" in a pasted update URL) must be
// \u-escaped too: a single raw newline makes /stats.json invalid and the dashboard stops updating.
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 8);
  for (char ch : s) {
    const unsigned char c = (unsigned char)ch;
    if (c == '"' || c == '\\') { o += '\\'; o += ch; }
    else if (c < 0x20) { char u[8]; snprintf(u, sizeof(u), "\\u%04x", c); o += u; }
    else o += ch;
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page_gz.h"   // dashboard HTML, gzipped at build time from page.h by tools/gzip_page.py — see issue #6

// /stats.json: read-only and stays open (the dashboard polls it), but the
// unauthenticated view is desensitized — masked MACs and no defcreds/upurl,
// which used to leak client fingerprints and a "is it using the placeholder
// password?" beacon to anyone on the LAN. An authenticated request (Basic
// Auth, no CSRF header needed for a harmless GET) gets the full data.
static void handleStats() {
  const bool authed = web.authenticate(WEB_USER, WEB_PASS);
  uint32_t up = millis() / 1000;
  char ut[40]; snprintf(ut, sizeof(ut), "%lud %luh %lum", (unsigned long)(up/86400), (unsigned long)((up%86400)/3600), (unsigned long)((up%3600)/60));
  // temperatureRead() can return NaN, and "nan" is not JSON: it would freeze the whole dashboard.
  const float tc = temperatureRead();
  const String temp = isnan(tc) ? String("null") : String(tc, 1);
  // Seconds until auto-resume, clamped at 0. loop() flips blockingOn back only on its own pass,
  // so for a moment resumeAt can already be in the past and the unsigned subtraction wrapped to ~4M s.
  const int32_t left = (!blockingOn && resumeAt) ? (int32_t)(resumeAt - millis()) : 0;
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + temp +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"dnsretry\":" + dnsRetry + ",\"dnsfail\":" + dnsFail + ",\"dnsstk\":" + (uint32_t)uxTaskGetStackHighWaterMark(dnsTaskH) +
             ",\"updnsip\":\"" + upstreamIp.toString() + "\",\"updnsport\":" + upstreamPort +
             ",\"defupdns\":\"" + DEFAULT_UPSTREAM.toString() + ":" + DEFAULT_UPSTREAM_PORT + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(left > 0 ? left / 1000 : 0);
  if (authed) {   // full picture only to the operator
    j += ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"";
    j += ",\"defcreds\":";
    // "default credentials" = either the secrets.example.h placeholders are
    // still compiled in, or the login is the well-known CI-baked pair
    // (admin/mingdai) that ships in the prebuilt docs/ firmware — anyone who
    // reads the repo can log in until the operator changes it.
    bool defc = (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 ||
                 strcmp(OTA_PASS,  "CHANGE_ME_OTA_PASSWORD")  == 0 ||
                 (strcmp(WEB_USER, "admin")  == 0 && strcmp(WEB_PASS, "mingdai") == 0));
    j += defc ? "true" : "false";
  }
  j += ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + (authed ? macStr(c.mac) : macMasked(c.mac)) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (!ip.fromString(web.arg("ip"))) { web.send(400, "text/plain", "IP 无效"); return; }
  // Toggle against bannedIP[] (what dnsQuery() actually enforces), not the Dev mirror, and don't
  // go through getClient(): that would add a phantom client row for an address that never queried.
  if (!setBan((uint32_t)ip, !isBannedIP((uint32_t)ip))) {
    web.send(507, "text/plain", String("封禁列表已满（最多 ") + MAX_BAN + " 个）");
    return;
  }
  saveBanned();
  web.send(200, "text/plain", "ok");
}

// /setcreds?user=…&pass=…&ota=… — change the dashboard login and/or the OTA
// key at runtime, no reflash. Authentication is plain requireAuth() like every
// other mutating endpoint: if the browser's cached Basic Auth no longer
// matches (right after a password change), the next request 401s and the
// browser pops its own login prompt — same flow as /ban, /upload, /forgetwifi.
// Each parameter is optional but at least one must be present.
// Charset: printable ASCII only, no space — safe to URL-encode and readable
// when typed on a phone. Length: user/pass/ota 1..32 / 4..64 / 4..64.
static bool validCred(const String& v, bool isUser, const char** why) {
  size_t min = isUser ? 1 : 4, max = isUser ? 32 : 64;
  if (v.length() < min) { *why = isUser ? "用户名至少 1 个字符" : "密码至少 4 个字符"; return false; }
  if (v.length() > max) { *why = isUser ? "用户名最多 32 个字符" : "密码最多 64 个字符"; return false; }
  for (size_t i = 0; i < v.length(); i++) {
    char c = v[i];
    if (c < 0x21 || c > 0x7e) { *why = "只能包含 ASCII 可见字符（不含空格）"; return false; }
  }
  return true;
}
static void handleSetCreds() {
  if (!requireAuth()) return;
  String nu = web.arg("user"), np = web.arg("pass"), no = web.arg("ota");
  if (!nu.length() && !np.length() && !no.length()) { web.send(400, "text/plain", "请至少填写一项"); return; }
  const char* why = nullptr;
  if (nu.length() && !validCred(nu, true,  &why)) { web.send(400, "text/plain", why); return; }
  if (np.length() && !validCred(np, false, &why)) { web.send(400, "text/plain", why); return; }
  if (no.length() && !validCred(no, false, &why)) { web.send(400, "text/plain", why); return; }
  prefs.begin("auth", false);
  if (nu.length()) prefs.putString("user", nu);
  if (np.length()) prefs.putString("pass", np);
  if (no.length()) prefs.putString("ota",  no);
  prefs.end();
  if (nu.length()) { authUserBuf = nu; WEB_USER = authUserBuf.c_str(); }
  if (np.length()) { authPassBuf = np; WEB_PASS = authPassBuf.c_str(); }
  if (no.length()) { authOtaBuf = no;  OTA_PASS = authOtaBuf.c_str(); }
  Serial.printf("[auth] creds changed (user=%d pass=%d ota=%d)\n", nu.length(), np.length(), no.length());
  // ArduinoOTA bakes its password into an MD5 challenge inside begin() and
  // setPassword() is a no-op afterwards (private _password, init-guarded) —
  // the only way to activate a new OTA key is a reboot. Only reboot when the
  // OTA key actually changed; user/pass changes apply live.
  if (no.length()) {
    web.send(200, "text/plain", "已更新，设备即将重启以启用新 OTA 密钥");
    delay(500); ESP.restart();
  }
  web.send(200, "text/plain", "已更新");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// Staging design: the new list streams to /blocklist.new, is validated, and
// only then the live file is replaced. A failed/interrupted/oversized transfer
// leaves the previous list fully intact (the old scheme deleted the live file
// before writing, so any failure permanently fail-opened the device).
// Peak space needs both files briefly; LittleFS has room for ~1 list — an
// update to an already near-full partition fails with "no space" and keeps
// the old list, which is the safe direction.
static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void stageBlocklist() { LittleFS.remove("/blocklist.new"); }   // fresh staging slot
// inFlash() binary-searches the file, so it is only usable as a whole number of 5-byte hashes in
// ascending order. Size alone can't tell a real list from an arbitrary file, a truncated
// transfer or a chunk-framed HTTP body, and an unsorted blob would silently stop blocking
// (by then the old list has already been replaced).
static bool stagedListSorted(File& f) {
  uint8_t chunk[HASH_BYTES * 256];
  uint64_t prev = 0; uint32_t rounds = 0;
  f.seek(0);
  for (;;) {
    int n = f.read(chunk, sizeof(chunk));
    if (n <= 0) break;
    if (n % HASH_BYTES) return false;
    for (int i = 0; i < n; i += HASH_BYTES) {
      const uint64_t v = unpackHash(chunk + i);
      if (v < prev) return false;
      prev = v;
    }
    if ((++rounds & 63) == 0) delay(1);          // let WiFi/idle tasks run during a ~1 MB scan
  }
  return true;
}
static bool commitBlocklist() {                  // validate /blocklist.new, then swap in
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0;
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0 && stagedListSorted(f);   // sorted 5-byte hashes
  if (f) f.close();
  ListLock lk;                                   // the DNS task must not touch the list while it is swapped
  if (ok) {
    if (blocklist) blocklist.close();            // release the live handle before swap
    LittleFS.remove(BLOCKLIST_PATH);             // only now does the old list go away
    ok = LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
    if (!ok) numHashes = 0;                      // rename failure: fail-open until next update
  } else {
    LittleFS.remove("/blocklist.new");           // live list untouched
  }
  reopenBlocklist();
  return ok;
}
static void abortBlocklist() { LittleFS.remove("/blocklist.new"); }   // live list untouched

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteOk = false;
static File upFile;
static void handleUploadDone() {
  // Consume the flag. Only the upload callback sets it, so a request without a file part (the
  // callback never runs) must not be vouched for by a *previous* upload's stale value.
  const bool authed = upAuthOk;
  upAuthOk = false;
  if (!authed) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: not a sorted 5-byte hash list, or no space left in the LittleFS partition (old list kept)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false;
      stageBlocklist();
      upFile = LittleFS.open("/blocklist.new", "w");
      upWriteOk = (bool)upFile;                  // sticky from here on: one failed write poisons the upload
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      // upWriteOk used to be re-set to true by every later successful chunk, so a failed middle
      // chunk (fs full) followed by a smaller last one that happened to fit passed as a good upload.
      if (upAuthOk && upFile && upWriteOk) {
        if (upFile.write(u.buf, u.currentSize) != u.currentSize) { upWriteOk = false; Serial.println("[ota] write failed (fs full?)"); }
      }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      if (upWriteOk) upOk = commitBlocklist();
      else { abortBlocklist(); upOk = false; }   // don't leave a half-written staging file filling the fs
      Serial.printf("[ota] %s -> %lu domains\n", upOk ? "OK" : "REJECTED", (unsigned long)numHashes);
      break;
    case UPLOAD_FILE_ABORTED: {
      const bool wasAuthed = upAuthOk;
      upAuthOk = false;                          // the "done" handler never runs for an aborted upload
      if (!wasAuthed) break;
      if (upFile) upFile.close();
      abortBlocklist();                          // old list stays live
      Serial.println("[ota] aborted");
      break;
    }
  }
}

// ---------- upstream resolver config (dashboard-configurable) ----------
// One line: "<ip>[:port]". Absent/blank file -> compile-time default.
static void loadUpstreamCfg() {
  File f = LittleFS.open("/upstream.cfg", "r"); if (!f) return;
  String l = f.readStringUntil('\n'); f.close(); l.trim(); if (!l.length()) return;
  int colon = l.lastIndexOf(':');
  String host = l; uint32_t port = 0;
  if (colon > 0) { host = l.substring(0, colon); port = l.substring(colon + 1).toInt(); }
  IPAddress ip;
  if (ip.fromString(host)) {                     // resolve on boot: reject hostnames
    upstreamIp = ip;
    if (port >= 1 && port <= 65535) upstreamPort = (uint16_t)port;
    Serial.printf("[upstream] %s:%u\n", upstreamIp.toString().c_str(), upstreamPort);
  } else {
    Serial.printf("[upstream] ignoring bad /upstream.cfg \"%s\"\n", l.c_str());
  }
}
static void saveUpstreamCfg() {
  File f = LittleFS.open("/upstream.cfg", "w"); if (!f) return;
  f.println(upstreamIp.toString() + ":" + upstreamPort); f.close();
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  f.close();
  if (iv.length()) {
    long h = iv.toInt();                         // signed first: a negative value must not wrap to a huge uint32
    if (h < 1) h = 1;
    if (h > (long)MAX_UPDATE_INTERVAL_H) h = MAX_UPDATE_INTERVAL_H;
    updateIntervalH = (uint32_t)h;
  }
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs;
  // Verify TLS properly against the embedded Mozilla CA bundle (setInsecure()
  // used to accept any forged cert — an on-path attacker could swap the hash
  // blob that commitBlocklist() accepts on size alone). WiFiClientSecure's
  // default state is neither insecure nor CA-armed, and ssl_client.cpp rejects
  // that with -1, so https:// would silently fail without this call.
  cs.setCACertBundle(x509_crt_bundle);
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "TLS begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  // Stream into the staging slot: the OLD list stays live while the download runs
  // (the old scheme deleted it up front and zeroed numHashes, so every failure
  // permanently fail-opened the device). DNS runs in its own task, so a 1 MB download no
  // longer blackholes the whole LAN's DNS for its duration.
  stageBlocklist();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis(); bool wok = true;
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      const int n = (int)stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) { if (f.write(b, (size_t)n) != (size_t)n) wok = false; total += (size_t)n; idle = millis(); }
    } else {
      if (millis() - idle > 15000) break;
    }
    delay(1);
  }
  f.close(); http.end();
  // A transfer cut short (idle timeout, dropped link) can still leave a file whose size happens to
  // be a multiple of 5, so completeness must be checked against Content-Length explicitly.
  const bool complete = (len < 0) || (total == (size_t)len);
  bool ok = false;
  if (wok && complete) ok = commitBlocklist();
  else abortBlocklist();                         // never leave a half-written staging file eating the fs
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains")
               : !complete ? ("incomplete download (" + String(total) + "/" + String(len) + "B) — old list kept")
                           : ("bad data or no space (" + String(total) + "B) — old list kept");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static bool fwDone   = false;                    // Update.end() succeeded for the current request
static void handleFwUpdateDone() {
  // Consume the flag: only the upload callback sets it, so a request without a file part must not
  // be vouched for (and, worse, rebooted on) by a stale value from an earlier upload.
  const bool authed = fwAuthOk;
  fwAuthOk = false;
  if (!authed) { web.requestAuthentication(); return; }
  const bool ok = fwDone && !Update.hasError();  // reboot only if an image was really committed
  fwDone = false;
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwDone = false;
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    fwDone = Update.end(true);
    if (fwDone) Serial.printf("[fw-ota] %lu bytes OK\n", (unsigned long)u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    const bool wasAuthed = fwAuthOk;
    fwAuthOk = false;                            // the "done" handler never runs for an aborted upload
    if (!wasAuthed) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><html lang=zh-CN><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<meta name=color-scheme content=light><meta name=theme-color content='#f5f7fa'>"
    "<title>C3 广告拦截器 · WiFi 设置</title><style>"
    ":root{--bg:#f5f7fa;--surface:#ffffff;--surface-2:#eef2f6;--line:#d9e1e9;--text:#17202d;--muted:#5b6a7c;--faint:#96a3b2;--accent:#0b7ea6;color-scheme:light}"
    "*{box-sizing:border-box}"
    "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;"
    "font:16px/1.6 -apple-system,'PingFang SC','Microsoft YaHei','Noto Sans CJK SC',system-ui,sans-serif;background:var(--bg);color:var(--text);"
    "-webkit-font-smoothing:antialiased}"
    ".card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:30px 26px 28px}"
    ".logo{display:inline-block;fill:var(--accent);vertical-align:middle}"
    ".brand{font-size:20px;font-weight:700;margin:12px 0 2px}.sub{color:var(--muted);font-size:14px;margin:0 0 6px}"
    "label{display:block;font-size:13px;color:var(--muted);margin:16px 0 7px}"
    "input{width:100%;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px}"
    "input:focus{outline:2px solid var(--accent);outline-offset:1px}input::placeholder{color:var(--faint)}"
    "button{width:100%;margin-top:22px;font:inherit;font-weight:600;border:0;border-radius:10px;padding:13px;background:var(--accent);color:#ffffff;cursor:pointer}"
    "button:hover{filter:brightness(1.07)}"
    "</style></head><body><div class=card>"
    "<svg class=logo width=30 height=30 viewBox='0 0 24 24' aria-hidden=true><path d='M12 2.5l7.5 3v5.2c0 4.6-3.2 8.6-7.5 10.8-4.3-2.2-7.5-6.2-7.5-10.8V5.5l7.5-3z'/><path d='M8.8 12l2.2 2.2 4.2-4.4' stroke='#fff' stroke-width=2 stroke-linecap=round stroke-linejoin=round fill=none/></svg>"
    "<div class=brand>C3 广告拦截器</div>"
    "<p class=sub>选择你的 WiFi 网络并输入密码，设备会重启并自动加入该网络。</p>"
    "<form method=POST action=/wifisave>"
    "<label for=s>WiFi 名称</label>"
    "<input id=s list=nets name=s placeholder='搜索网络…' required>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<label for=p>密码</label>"
    "<input id=p name=p type=password placeholder='WiFi 密码'>"
    "<button>连接</button>"
    "</form></div></body></html>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><html lang=zh-CN><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                             "<meta name=color-scheme content=light>"
                             "<body style=\"margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:20px;"
                             "font:16px/1.7 -apple-system,'PingFang SC','Microsoft YaHei','Noto Sans CJK SC',system-ui,sans-serif;background:#f5f7fa;color:#17202d\">"
                             "<div style=\"max-width:400px\">"
                             "<svg width=\"46\" height=\"46\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"10\" fill=\"#15803d\"/><path d=\"M8 12.5l2.6 2.6L16 9.5\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" fill=\"none\"/></svg>"
                             "<h2 style=\"margin:14px 0 6px;font-size:20px\">已保存，正在重启并连接</h2>"
                             "<p style=\"margin:0;color:#5b6a7c\">正在加入 <b style=\"color:#17202d\">" + htmlEscape(ss) + "</b>&hellip;</p>"
                             "<p style=\"margin-top:20px;color:#5b6a7c;font-size:14px\">把手机重新连回你自己的 WiFi，然后在 <b style=\"color:#0b7ea6\">c3adblock.local</b> 找到设备。</p>"
                             "</div></body></html>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  // connectWiFi() can give up with the STA still mid-"connecting", and a scan can't run reliably
  // in that state (it fails and the portal shows an empty network list): stop the join first.
  WiFi.disconnect(); delay(100);
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); bootGestStep(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  listMux = xSemaphoreCreateMutex();
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  abortBlocklist();                  // drop a half-written staging file left by a reset/power loss mid-update
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %lu domains\n", (unsigned long)numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg(); loadUpstreamCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // BOOT button + on-board LED. Formerly this spot held a "BOOT held at
  // power-on -> wipe" block, but on the C3 BOOT is the boot-mode strapping
  // pin: holding it across a reset sends the chip into ROM download mode and
  // the app never runs, so that branch was dead code. The live gesture
  // (double-tap + long-press) runs in loop() instead — see bootGestStep().
  pinMode(BOOT_PIN, INPUT_PULLUP);
  ledInit();
  bootGest = BG_IDLE; bootGestT = millis();

  // Runtime creds (NVS namespace "auth") override secrets.h, so a /setcreds
  // change survives power-cycle. Sits before the placeholder check below so the
  // warning banner and /stats.json's defcreds reflect the *live* login.
  loadAuth();

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  // SNTP: blocklist TLS verification (fetchBlocklist) needs the wall clock to
  // sit inside the cert's validity window; on boot the RTC reads 1970, so
  // start syncing immediately. UTC+8 default offset keeps serial logs readable.
  configTime(8 * 3600, 0, "cn.pool.ntp.org", "pool.ntp.org", "time.google.com");
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsStart();
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.sendHeader("Content-Encoding", "gzip"); web.send_P(200, "text/html", (const char*)PAGE_GZ, PAGE_GZ_LEN); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/setcreds", handleSetCreds);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    if (addCustom(web.arg("d"))) web.send(200, "text/plain", "ok");
    else web.send(400, "text/plain", "域名无效、已存在，或自定义列表已满（最多 " + String(MAX_CUSTOM) + " 条）");
  });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    // loop()'s wrap-safe "(int32_t)(millis() - resumeAt) >= 0" only holds for < ~24 days, and
    // s * 1000 overflows 32 bits above ~49 days: either would end the pause immediately.
    if (s > 7L * 86400) s = 7L * 86400;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    if (s > 0 && resumeAt == 0) resumeAt = 1;    // 0 is reserved for "paused until resumed manually"
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) {
      // The URL is persisted one-per-line (update.cfg) and echoed into /stats.json: a control
      // character corrupts both, and HTTPClient can't speak anything but http(s) anyway.
      String u = web.arg("u"); u.trim();
      bool good = u.length() == 0 || ((u.startsWith("http://") || u.startsWith("https://")) && u.length() < 512);
      for (size_t i = 0; good && i < u.length(); i++) if ((uint8_t)u[i] < 0x20 || (uint8_t)u[i] == 0x7f) good = false;
      if (!good) { web.send(400, "text/plain", "更新地址必须以 http:// 或 https:// 开头"); return; }
      updateUrl = u;
    }
    if (web.hasArg("h")) {
      long h = web.arg("h").toInt();             // signed first: a negative value must not wrap to a huge uint32
      if (h < 1) h = 1;
      if (h > (long)MAX_UPDATE_INTERVAL_H) h = MAX_UPDATE_INTERVAL_H;
      updateIntervalH = (uint32_t)h;
    }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  // /setupstream?ip=1.1.1.1&port=53   (port optional, defaults to 53)
  // Applied immediately: the DNS task reads upstreamIp/Port for every send.
  web.on("/setupstream", []() {
    if (!requireAuth()) return;
    String ip = web.arg("ip"); ip.trim();
    if (!ip.length()) { web.send(400, "text/plain", "缺少 IP"); return; }
    IPAddress ipr;
    if (!ipr.fromString(ip)) { web.send(400, "text/plain", "IP 无效，需要如 1.1.1.1 这样的 IPv4 地址"); return; }
    // Pointing upstream at ourselves would forward every allowed query straight
    // back into this same server — an instant packet loop.
    if (ipr == WiFi.localIP() || ipr == IPAddress(127, 0, 0, 1) || (uint32_t)ipr == 0) {
      web.send(400, "text/plain", "不能把自己设为上游"); return;
    }
    uint32_t port = web.hasArg("port") && web.arg("port").length() ? web.arg("port").toInt() : DEFAULT_UPSTREAM_PORT;
    if (port < 1 || port > 65535) { web.send(400, "text/plain", "端口需在 1-65535"); return; }
    upstreamIp = ipr; upstreamPort = (uint16_t)port;
    saveUpstreamCfg();
    Serial.printf("[upstream] set to %s:%u\n", upstreamIp.toString().c_str(), upstreamPort);
    web.send(200, "text/plain", "ok");
  });
  // /resetupstream -> back to the compiled-in default
  web.on("/resetupstream", []() {
    if (!requireAuth()) return;
    upstreamIp = DEFAULT_UPSTREAM; upstreamPort = DEFAULT_UPSTREAM_PORT;
    LittleFS.remove("/upstream.cfg");            // absent file == compiled-in default (see loadUpstreamCfg),
                                                 // so a later firmware with a different UPSTREAM_IP isn't overridden
    web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bootGestStep();   // tap-tap-hold, then one more tap → wipe credentials (LED lit while armed)
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  delay(1);
}
