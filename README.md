==========================================================
SONOCRYPT - GUIA RAPIDA
==========================================================

Transmision de mensajes de texto por audio (data-over-sound)
con cifrado AES-256-GCM opcional.



INSTALACION



pip install sounddevice scipy



1. ENVIAR UN MENSAJE A UN ARCHIVO WAV


# Mensaje en claro
python sonocrypt.py send "hola mundo"

# Mensaje cifrado con contrasena
python sonocrypt.py send "mensaje secreto" "mi-clave"

Genera "mensaje.wav" en la carpeta actual
(mono, 16-bit, 44 100 Hz).



2. RECIBIR/DECODIFICAR UN ARCHIVO WAV


# Mensaje en claro
python sonocrypt.py recv mensaje.wav

# Mensaje cifrado (misma contrasena usada al enviar)
python sonocrypt.py recv mensaje.wav "mi-clave"

Devuelve el texto, o None si la clave es incorrecta o el
audio esta muy degradado.
