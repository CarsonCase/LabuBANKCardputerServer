build:
	arduino-cli compile --fqbn m5stack:esp32:m5stack_cardputer .

upload:
	arduino-cli upload -p /dev/ttyACM0 --fqbn m5stack:esp32:m5stack_cardputer .

logs:
	arduino-cli monitor -p /dev/ttyACM0 -c baudrate=115200