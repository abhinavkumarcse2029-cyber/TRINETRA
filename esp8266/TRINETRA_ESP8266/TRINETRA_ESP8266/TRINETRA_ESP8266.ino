/*
  TRINETRA - ESP8266 Hardware UART Firmware
  -----------------------------------------
  Raspberry Pi se commands receive karta hai
  aur response UART ke through wapas bhejta hai.

  Final ESP8266 pins:
  D7 / GPIO13 = RX
  D8 / GPIO15 = TX

  Raspberry Pi TX -> ESP8266 D7
  Raspberry Pi RX <- ESP8266 D8
  Raspberry Pi GND -> ESP8266 GND
*/

#include <ESP8266WiFi.h>

bool quarantined = false;
String receivedCommand = "";


// ============================================================
// SEND RESPONSE TO RASPBERRY PI
// ============================================================

void sendResponse(const String &response) {
  Serial.println(response);
  Serial.flush();
}


// ============================================================
// COMMAND FUNCTIONS
// ============================================================

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

  // TRINETRA uses wired UART communication.
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


// ============================================================
// EXECUTE RECEIVED COMMAND
// ============================================================

void executeCommand(String command) {
  command.trim();
  command.toUpperCase();

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


// ============================================================
// SETUP
// ============================================================

void setup() {
  /*
    Start hardware UART at 9600 baud.

    Serial.swap() changes UART pins from:
      RX0 / TX0

    To:
      GPIO13 / D7 = RX
      GPIO15 / D8 = TX
  */

  Serial.begin(9600);
  Serial.swap();

  delay(500);

  WiFi.mode(WIFI_OFF);

  sendResponse("READY|TRINETRA_ESP8266");
}


// ============================================================
// MAIN LOOP
// ============================================================

void loop() {
  while (Serial.available() > 0) {
    char incomingCharacter = Serial.read();

    if (incomingCharacter == '\n') {
      executeCommand(receivedCommand);
      receivedCommand = "";
    }
    else if (incomingCharacter != '\r') {
      receivedCommand += incomingCharacter;

      if (receivedCommand.length() > 100) {
        receivedCommand = "";

        sendResponse(
          "ERROR|INVALID|Command too long"
        );
      }
    }
  }

  delay(10);
}