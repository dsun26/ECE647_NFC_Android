NFC application for ECE647

Acts like a NFC messenger

Phone in write mode

	-Sends the written string when phones are close enough for NFC

	-If user enters a secret key, the string to be sent is encrypted using AES with that secret key string as a "password"

Phone in read mode

	-Displays the received string

	-If user enters a secret key, the received string is decrypted using AES with that secret key string as a "password"

Uses NDEF Messages and Records
