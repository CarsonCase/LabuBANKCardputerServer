#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include "ethers.h"
#include "uECC.h"
#include <M5Cardputer.h>

const char* ssid = "";
const char* password = "";

WebServer server(80);

// Hardcoded private key (32 bytes in hex format)
// WARNING: In production, store this securely!
// 0x94544835Cf97c631f101c5f538787fE14E2E04f6
const char* privateKeyHex = "";

void showMainTitle() {
    M5Cardputer.Display.drawRoundRect(10, 10, 220, 30, 5, TFT_DARKCYAN); // Around main title
    M5Cardputer.Display.setTextColor(TFT_DARKCYAN);
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setCursor(19, 18);
    M5Cardputer.Display.printf("LabuBANK");
}

void playPingSound() {
  // Pleasant notification chime - ascending notes
  M5Cardputer.Speaker.tone(523, 80);   // C5 - clean start
  delay(80);
  M5Cardputer.Speaker.tone(659, 120);  // E5 - bright middle
  delay(60);
  M5Cardputer.Speaker.tone(784, 160);  // G5 - warm finish
  delay(80);
  M5Cardputer.Speaker.end();
}

// Play a custom melody
void playSuccessSound() {
  // Mario theme intro
  M5Cardputer.Speaker.tone(659, 125);  // E5
  delay(125);
  M5Cardputer.Speaker.tone(659, 125);  // E5
  delay(125);
  M5Cardputer.Speaker.tone(659, 125);  // E5
  delay(125);
  M5Cardputer.Speaker.tone(523, 125);  // C5
  delay(125);
  M5Cardputer.Speaker.tone(659, 125);  // E5
  delay(125);
  M5Cardputer.Speaker.tone(784, 250);  // G5
  delay(250);
  M5Cardputer.Speaker.end();
}


static inline uint8_t hexNib(char c) {
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
  return 0;
}

void hexToBytes(const String &hexIn, uint8_t *out, size_t *outLen) {
  String s = hexIn;
  if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
  int n = s.length();
  if (n == 0) { *outLen = 0; return; }
  int i = 0, j = 0;
  if (n % 2 == 1) {
    out[j++] = hexNib(s.charAt(0));
    i = 1;
  }
  for (; i < n; i += 2) {
    out[j++] = (uint8_t)((hexNib(s.charAt(i)) << 4) | hexNib(s.charAt(i+1)));
  }
  *outLen = j;
}

void hexStringToBytes(const char* hexString, uint8_t* bytes, int length) {
  for (int i = 0; i < length; i++) {
    sscanf(hexString + 2*i, "%2hhx", &bytes[i]);
  }
}

String bytesToHexString(uint8_t* bytes, int length) {
  String result = "";
  for (int i = 0; i < length; i++) {
    if (bytes[i] < 16) result += "0";
    result += String(bytes[i], HEX);
  }
  return result;
}

size_t trimLeadingZeros(const uint8_t *buf, size_t len) {
  size_t i = 0;
  while (i < len && buf[i] == 0x00) i++;
  return i;
}

// decimal ASCII -> minimal big-endian bytes
void decStringToBytes(const String &dec, uint8_t *out, size_t *outLen) {
  uint8_t tmp[32]; for (int i = 0; i < 32; i++) tmp[i] = 0;
  bool allZero = true;
  for (size_t k = 0; k < dec.length(); k++) {
    char c = dec.charAt(k);
    if (c < '0' || c > '9') continue;
    uint8_t digit = (uint8_t)(c - '0');
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
      uint16_t val = (uint16_t)tmp[i] * 10 + carry;
      tmp[i] = (uint8_t)(val & 0xFF);
      carry = (uint16_t)(val >> 8);
    }
    int i = 31;
    uint16_t add = tmp[i] + digit;
    tmp[i] = (uint8_t)(add & 0xFF);
    uint16_t c2 = (uint16_t)(add >> 8);
    i--;
    while (c2 && i >= 0) {
      uint16_t add2 = tmp[i] + c2;
      tmp[i] = (uint8_t)(add2 & 0xFF);
      c2 = (uint16_t)(add2 >> 8);
      i--;
    }
    if (digit != 0) allZero = false;
  }
  if (allZero) { *outLen = 0; return; }
  size_t off = trimLeadingZeros(tmp, 32);
  *outLen = 32 - off;
  memcpy(out, tmp + off, *outLen);
}

void appendByteHex(uint8_t b, String &out) {
  const char *hex = "0123456789abcdef";
  out += hex[b >> 4];
  out += hex[b & 0x0F];
}

String rlpEncodeItem(const uint8_t *data, size_t len) {
  String out = "";
  if (len == 1 && data[0] <= 0x7f) {
    appendByteHex(data[0], out);
    return out;
  }
  if (len <= 55) {
    appendByteHex((uint8_t)(0x80 + len), out);
  } else {
    uint8_t lenbuf[8]; int l = 0;
    size_t x = len;
    while (x > 0) { lenbuf[l++] = (uint8_t)(x & 0xFF); x >>= 8; }
    appendByteHex((uint8_t)(0xb7 + l), out);
    for (int i = l - 1; i >= 0; i--) appendByteHex(lenbuf[i], out);
  }
  for (size_t i = 0; i < len; i++) appendByteHex(data[i], out);
  return out;
}

String rlpEncodeListHeader(size_t payloadLen) {
  String out = "";
  if (payloadLen <= 55) {
    appendByteHex((uint8_t)(0xc0 + payloadLen), out);
  } else {
    uint8_t lenbuf[8]; int l = 0;
    size_t x = payloadLen;
    while (x > 0) { lenbuf[l++] = (uint8_t)(x & 0xFF); x >>= 8; }
    appendByteHex((uint8_t)(0xf7 + l), out);
    for (int i = l - 1; i >= 0; i--) appendByteHex(lenbuf[i], out);
  }
  return out;
}

// secp256k1 n and n/2 constants (big-endian)
static const uint8_t SECP256K1_N[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
  0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint8_t SECP256K1_N_HALF[32] = {
  0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

int bigCompare(const uint8_t *a, const uint8_t *b, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

void bigSub(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len) {
  int16_t carry = 0;
  for (int i = (int)len - 1; i >= 0; i--) {
    int16_t x = (int16_t)a[i] - (int16_t)b[i] - carry;
    if (x < 0) { x += 256; carry = 1; } else { carry = 0; }
    out[i] = (uint8_t)x;
  }
}

void canonicalizeS(uint8_t *sig64) {
  // sig64 = r(0..31) || s(32..63)
  if (bigCompare(sig64 + 32, SECP256K1_N_HALF, 32) > 0) {
    uint8_t sNew[32];
    bigSub(SECP256K1_N, sig64 + 32, sNew, 32);
    memcpy(sig64 + 32, sNew, 32);
  }
}

// Random number generator function for micro-ECC
int esp_random(uint8_t *dest, unsigned size) {
  for (unsigned i = 0; i < size; i++) {
    dest[i] = random(256);
  }
  return 1;
}

String buildAndSignLegacyTx(const String &to, const String &value, const String &data, const String &gasLimit, const String &gasPrice, const String &nonce, const String &chainIdStr, String &r_hex, String &s_hex, String &v0_hex, String &v1_hex, String &rawTx_v0, String &rawTx_v1, String &signingPayloadHex) {
  uint8_t nonce_bytes[32]; size_t nonce_len = 0; decStringToBytes(nonce, nonce_bytes, &nonce_len);
  uint8_t gasPrice_bytes[32]; size_t gasPrice_len = 0; decStringToBytes(gasPrice, gasPrice_bytes, &gasPrice_len);
  uint8_t gasLimit_bytes[32]; size_t gasLimit_len = 0; decStringToBytes(gasLimit, gasLimit_bytes, &gasLimit_len);
  uint8_t value_bytes[32]; size_t value_len = 0; decStringToBytes(value, value_bytes, &value_len);
  uint8_t to_bytes[20]; size_t to_len = 0; hexToBytes(to, to_bytes, &to_len);
  uint8_t data_bytes[768]; size_t data_len = 0; hexToBytes(data, data_bytes, &data_len);
  uint8_t chainId_bytes[32]; size_t chainId_len = 0; decStringToBytes(chainIdStr, chainId_bytes, &chainId_len);

  String payloadHex = ""; size_t payloadLen = 0; String enc;
  enc = rlpEncodeItem(nonce_bytes, nonce_len);        payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(gasPrice_bytes, gasPrice_len);  payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(gasLimit_bytes, gasLimit_len);  payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(to_bytes, to_len);              payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(value_bytes, value_len);        payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(data_bytes, data_len);          payloadHex += enc; payloadLen += enc.length() / 2;
  enc = rlpEncodeItem(chainId_bytes, chainId_len);    payloadHex += enc; payloadLen += enc.length() / 2;
  // r = 0
  enc = rlpEncodeItem(NULL, 0);                       payloadHex += enc; payloadLen += enc.length() / 2;
  // s = 0
  enc = rlpEncodeItem(NULL, 0);                       payloadHex += enc; payloadLen += enc.length() / 2;

  String listPrefix = rlpEncodeListHeader(payloadLen);
  signingPayloadHex = listPrefix + payloadHex;

  // Hash signing payload bytes
  String signHexPrefixed = "0x" + signingPayloadHex;
  uint8_t signBytes[1024]; size_t signBytesLen = 0; hexToBytes(signHexPrefixed, signBytes, &signBytesLen);
  uint8_t hash[32]; ethers_keccak256(signBytes, (uint16_t)signBytesLen, hash);

  // Sign
  uint8_t privateKey[32]; hexStringToBytes(privateKeyHex, privateKey, 32);
  uint8_t signature[64];
  uECC_set_rng(&esp_random);
  if (!ethers_sign(privateKey, hash, signature)) {
    return String("");
  }
  canonicalizeS(signature);

  String sigHex = bytesToHexString(signature, 64);
  r_hex = sigHex.substring(0, 64);
  s_hex = sigHex.substring(64, 128);

  // Compute v candidates (EIP-155): v = chainId*2 + 35 + recId
  // We do not compute recId here; return both possibilities
  // Convert chainId to integer (fits in 32-bit for common chains)
  uint32_t chainId32 = (uint32_t) strtoul(chainIdStr.c_str(), NULL, 10);
  uint32_t v0 = chainId32 * 2 + 35; // recId = 0
  uint32_t v1 = v0 + 1;             // recId = 1
  v0_hex = String(v0, HEX);
  v1_hex = String(v1, HEX);

  // Build raw tx for both v values
  uint8_t v0_bytes[8]; size_t v0_len = 0; {
    String v0_dec = String(v0);
    decStringToBytes(v0_dec, v0_bytes, &v0_len);
  }
  uint8_t v1_bytes[8]; size_t v1_len = 0; {
    String v1_dec = String(v1);
    decStringToBytes(v1_dec, v1_bytes, &v1_len);
  }
  // Prepare r, s trimmed
  uint8_t r_bytes[32]; size_t r_len = 0; {
    String r_pref = "0x" + r_hex; hexToBytes(r_pref, r_bytes, &r_len);
  }
  uint8_t s_bytes[32]; size_t s_len = 0; {
    String s_pref = "0x" + s_hex; hexToBytes(s_pref, s_bytes, &s_len);
  }
  size_t r_off = trimLeadingZeros(r_bytes, r_len);
  size_t s_off = trimLeadingZeros(s_bytes, s_len);

  // Common first 6 fields
  String baseHex = ""; size_t baseLen = 0;
  enc = rlpEncodeItem(nonce_bytes, nonce_len);        baseHex += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(gasPrice_bytes, gasPrice_len);  baseHex += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(gasLimit_bytes, gasLimit_len);  baseHex += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(to_bytes, to_len);              baseHex += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(value_bytes, value_len);        baseHex += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(data_bytes, data_len);          baseHex += enc; baseLen += enc.length() / 2;

  // v0 raw tx
  String payloadHex_v0 = baseHex;
  enc = rlpEncodeItem(v0_bytes, v0_len);              payloadHex_v0 += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(r_bytes + r_off, r_len - r_off);payloadHex_v0 += enc; baseLen += enc.length() / 2;
  enc = rlpEncodeItem(s_bytes + s_off, s_len - s_off);payloadHex_v0 += enc; baseLen += enc.length() / 2;
  String listPrefix_v0 = rlpEncodeListHeader(baseLen);
  rawTx_v0 = "0x" + listPrefix_v0 + payloadHex_v0;

  // v1 raw tx
  size_t baseLen_v1 = (baseHex.length() / 2);
  String payloadHex_v1 = baseHex;
  enc = rlpEncodeItem(v1_bytes, v1_len);              payloadHex_v1 += enc; baseLen_v1 += enc.length() / 2;
  enc = rlpEncodeItem(r_bytes + r_off, r_len - r_off);payloadHex_v1 += enc; baseLen_v1 += enc.length() / 2;
  enc = rlpEncodeItem(s_bytes + s_off, s_len - s_off);payloadHex_v1 += enc; baseLen_v1 += enc.length() / 2;
  String listPrefix_v1 = rlpEncodeListHeader(baseLen_v1);
  rawTx_v1 = "0x" + listPrefix_v1 + payloadHex_v1;

  return String("ok");
}

void waitForConfirmation(const char* message) {
  M5Cardputer.Display.clear();
  showMainTitle();
  
  // Display confirmation message
  M5Cardputer.Display.setTextColor(TFT_WHITE);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setCursor(10, 50);
  M5Cardputer.Display.printf("Confirm: %s", message);
  
  // Display instruction
  M5Cardputer.Display.setCursor(10, 70);
  
  // Wait for Enter key
  while (true) {
    M5Cardputer.update();
    
    if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
      // Small delay to debounce
      delay(100);
      break;
    }
    
    delay(50);
  }
  
  // Clear the confirmation message
  M5Cardputer.Display.clear();
  showMainTitle();
  M5Cardputer.Display.setTextColor(TFT_WHITE);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setCursor(10, 50);
  M5Cardputer.Display.printf("IP: %s", WiFi.localIP().toString().c_str());
}

void handlePreflight() {
  Serial.println("Preflight request received");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server.send(200, "text/plain", "");
}

void handleSign() {
  Serial.println("Sign request received");
  playPingSound();
  // Add CORS headers to all responses
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");

  if (server.method() != HTTP_POST) {
    server.send(405, "application/json", "{\"error\":\"Method not allowed\"}");
    return;
  }

  String body = server.arg("plain");
  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, body);
  if (error) {
    server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
    return;
  }

  String confirmMsg = String("Confirm transaction?\n\nTo: ") + doc["to"].as<String>() + 
                     String("\n\n\nValue: ") + doc["value"].as<String>() + 
                     String("\n\nData: ") + doc["data"].as<String>() +
                     String("\n\Press Enter to Continue");
  waitForConfirmation(confirmMsg.c_str());

  String unsignedRlp = doc["unsignedRlp"] | ""; // optional 0x... preimage like Firefly
  String to = doc["to"] | "";
  String value = doc["value"] | "0";
  String data = doc["data"] | "0x";
  String gasLimit = doc["gasLimit"] | "21000";
  String gasPrice = doc["gasPrice"] | "20000000000";
  String nonce = doc["nonce"] | "0";
  String chainId = doc["chainId"] | "1";

  uint8_t privateKey[32];
  hexStringToBytes(privateKeyHex, privateKey, 32);

  DynamicJsonDocument response(3072);

  if (unsignedRlp.length() > 0) {
    // Sign the provided preimage (must be EIP-155 payload [.., chainId, 0, 0])
    uint8_t preimage[1024]; size_t preimageLen = 0;
    hexToBytes(unsignedRlp, preimage, &preimageLen);
    if (preimageLen == 0) {
      server.send(400, "application/json", "{\"error\":\"unsignedRlp invalid\"}");
      return;
    }

    uint8_t hash[32]; ethers_keccak256(preimage, (uint16_t)preimageLen, hash);
    uint8_t signature[64]; uECC_set_rng(&esp_random);
    if (!ethers_sign(privateKey, hash, signature)) {
      server.send(500, "application/json", "{\"error\":\"Signing failed\"}");
      return;
    }

    canonicalizeS(signature);
    String sigHex = bytesToHexString(signature, 64);
    String r_hex = sigHex.substring(0, 64);
    String s_hex = sigHex.substring(64, 128);

    response["signature"] = sigHex + ""; // r||s
    response["r"] = String("0x") + r_hex;
    response["s"] = String("0x") + s_hex;
    response["signingPayload"] = unsignedRlp;
    // v cannot be derived here without recovery; client should compute recId and rawTx

  } else {
    // Build EIP-155 preimage, sign, and return rawTx candidates
    String r_hex, s_hex, v0_hex, v1_hex, rawTx_v0, rawTx_v1, signingPayloadHex;
    String ok = buildAndSignLegacyTx(to, value, data, gasLimit, gasPrice, nonce, chainId,
                                     r_hex, s_hex, v0_hex, v1_hex, rawTx_v0, rawTx_v1, signingPayloadHex);
    if (ok == "") {
      server.send(500, "application/json", "{\"error\":\"Signing failed\"}");
      return;
    }

    response["r"] = String("0x") + r_hex;
    response["s"] = String("0x") + s_hex;
    response["v"] = String("0x") + v0_hex;
    response["signature"] = String(r_hex) + String(s_hex);
    response["transactionData"]["nonce"] = nonce;
    response["transactionData"]["gasPrice"] = gasPrice;
    response["transactionData"]["gasLimit"] = gasLimit;
    response["transactionData"]["to"] = to;
    response["transactionData"]["value"] = value;
    response["transactionData"]["data"] = data;
    response["transactionData"]["chainId"] = chainId;
    response["rawTransaction"] = rawTx_v0; // default to recId 0
    response["signingPayload"] = String("0x") + signingPayloadHex;
  }

  String responseStr; serializeJson(response, responseStr);
  playSuccessSound();
  server.send(200, "application/json", responseStr);
}

void setup() {
  Serial.begin(115200);

  // Initialize M5Cardputer
  auto cfg = M5.config();
  M5Cardputer.begin(cfg);
  
  // Clear display and show title
  M5Cardputer.Display.clear();

  randomSeed(analogRead(0));
  uECC_set_rng(&esp_random);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }

  Serial.println("Connected to WiFi");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Show IP address on display
  M5Cardputer.Display.clear();
  showMainTitle();
  M5Cardputer.Display.setTextColor(TFT_WHITE);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setCursor(10, 50);
  M5Cardputer.Display.printf("IP: %s", WiFi.localIP().toString().c_str());

  // Add OPTIONS handler for CORS preflight
  server.on("/sign", HTTP_OPTIONS, handlePreflight);
  server.on("/sign", HTTP_POST, handleSign);

  server.begin();
  Serial.println("Ethereum Signing Server started");
}

void loop() {
  server.handleClient();
}
