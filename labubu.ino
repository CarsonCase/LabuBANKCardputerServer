#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include "ethers.h"

const char* ssid = "SSID";
const char* password = "Password";

WebServer server(80);

// Hardcoded private key (32 bytes in hex format)
// WARNING: In production, store this securely!
const char* privateKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

void handleRoot() {
  // Send a simple info page
  String html = "<!DOCTYPE html><html><head><title>Ethereum Signing Server</title></head>";
  html += "<body><h1>Ethereum Signing Server</h1>";
  html += "<p>POST to /sign with JSON payload containing transaction data</p>";
  html += "<p>Example: {\"to\":\"0x...\", \"value\":\"1000000000000000000\", \"data\":\"0x\"}</p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleSign() {
  if (server.method() != HTTP_POST) {
    server.send(405, "application/json", "{\"error\":\"Method not allowed\"}");
    return;
  }

  // Parse JSON payload
  String body = server.arg("plain");
  DynamicJsonDocument doc(1024);
  DeserializationError error = deserializeJson(doc, body);
  
  if (error) {
    server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
    return;
  }

  // Extract transaction parameters
  String to = doc["to"] | "";
  String value = doc["value"] | "0";
  String data = doc["data"] | "0x";
  String gasLimit = doc["gasLimit"] | "21000";
  String gasPrice = doc["gasPrice"] | "20000000000";
  String nonce = doc["nonce"] | "0";

  // Create transaction hash (simplified - you'd normally use RLP encoding)
  String transactionData = to + value + data + gasLimit + gasPrice + nonce;
  
  // Sign the transaction
  String signature = signTransaction(transactionData);
  
  if (signature == "") {
    server.send(500, "application/json", "{\"error\":\"Signing failed\"}");
    return;
  }

  // Return signed transaction
  DynamicJsonDocument response(512);
  response["signature"] = signature;
  response["r"] = signature.substring(0, 64);
  response["s"] = signature.substring(64, 128);
  response["v"] = signature.substring(128);
  
  String responseStr;
  serializeJson(response, responseStr);
  
  server.send(200, "application/json", responseStr);
  Serial.println("Transaction signed successfully");
}

String signTransaction(String transactionData) {
  // Convert hex private key to bytes
  uint8_t privateKey[32];
  hexStringToBytes(privateKeyHex, privateKey, 32);
  
  // Create hash of transaction data using Keccak256
  uint8_t hash[32];
  ethers_keccak256((uint8_t*)transactionData.c_str(), transactionData.length(), hash);
  
  // Sign the hash using micro-ECC
  uint8_t signature[64];
  if (!ethers_sign(privateKey, hash, signature)) {
    return "";
  }
  
  // Convert to hex string (r + s + v)
  String result = bytesToHexString(signature, 64) + "1c"; // v = 28 (0x1c)
  return result;
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

void setup() {
  Serial.begin(115200);

  // Connect to Wi-Fi network
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }

  Serial.println("Connected to WiFi");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Set up the routes for handling HTTP requests
  server.on("/", handleRoot);
  server.on("/sign", handleSign);

  // Start the server
  server.begin();
  Serial.println("Ethereum Signing Server started");
}

void loop() {
  // Handle incoming HTTP requests
  server.handleClient();
}
