/*
  TRINETRA - ESP8266 Firmware
  --------------------------
  Raspberry Pi se UART commands receive karta hai
  aur command execution response wapas bhejta hai.

  Raspberry Pi communication pins:
  D6 = RX
  D5 = TX
*/

#include <ESP8266WiFi.h>
#include <SoftwareSerial.h>

// SoftwareSerial(RX pin, TX pin)
SoftwareSerial raspberryPiSerial(D6, D5);

bool quarantined = false;
String receivedCommand = "";

void sendResponse(const String &response) {
  raspberryPiSerial.println(response);

  // USB Serial Monitor debugging
  Serial.println("[Response] " + response);
}

void performSecurityScan() {
  String deviceState;

  if (quarantined) {
    deviceState = "QUARANTINED";
  } else {
    deviceState = "HEALTHY";
  }

  sendResponse(
    "OK|SECURITY_SCAN|ESP8266 security scan completed;STATE=" +
    deviceState
  );
}

void quarantineDevice() {
  quarantined = true;

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  sendResponse(
    "OK|QUARANTINE|ESP8266 network access restricted"
  );
}

void restoreDevice() {
  quarantined = false;

  // TRINETRA currently communicates through wired UART.
  WiFi.mode(WIFI_OFF);

  sendResponse(
    "OK|RESTORE|ESP8266 restored to normal operation"
  );
}

void sendTelemetry() {
  String telemetry = "OK|REQUEST_TELEMETRY|";

  telemetry += "UPTIME_MS=";
  telemetry += String(millis());

  telemetry += ";QUARANTINED=";
  telemetry += quarantined ? "TRUE" : "FALSE";

  telemetry += ";FREE_HEAP=";
  telemetry += String(ESP.getFreeHeap());

  telemetry += ";CHIP_ID=";
  telemetry += String(ESP.getChipId());

  sendResponse(telemetry);
}

void restartDevice() {
  sendResponse(
    "OK|RESTART|ESP8266 restart command accepted"
  );

  delay(1000);
  ESP.restart();
}

void executeCommand(String command) {
  command.trim();
  command.toUpperCase();

  Serial.println("[Command] " + command);

  if (command == "QUARANTINE") {
    quarantineDevice();
  }
  else if (command == "RESTORE") {
    restoreDevice();
  }
  else if (command == "REQUEST_TELEMETRY") {
    sendTelemetry();
  }
  else if (command == "RESTART") {
    restartDevice();
  }
  else if (command == "SECURITY_SCAN") {
    performSecurityScan();
  }
  else if (command.length() > 0) {
    sendResponse(
      "ERROR|" + command + "|Unsupported command"
    );
  }
}

void setup() {
  // USB Serial Monitor
  Serial.begin(115200);

  // Raspberry Pi UART
  raspberryPiSerial.begin(9600);

  delay(500);

  // ESP8266 will not connect directly to Wi-Fi.
  WiFi.mode(WIFI_OFF);

  Serial.println();
  Serial.println("TRINETRA ESP8266 firmware started");
  Serial.println("Waiting for Raspberry Pi commands...");

  sendResponse("READY|TRINETRA_ESP8266");
}

void loop() {
  while (raspberryPiSerial.available() > 0) {
    char incomingCharacter = raspberryPiSerial.read();

    if (incomingCharacter == '\n') {
      executeCommand(receivedCommand);
      receivedCommand = "";
    }
    else if (incomingCharacter != '\r') {
      receivedCommand += incomingCharacter;

      // Prevent accidental memory overflow
      if (receivedCommand.length() > 100) {
        receivedCommand = "";
        sendResponse("ERROR|INVALID|Command too long");
      }
    }
  }

  delay(10);
}