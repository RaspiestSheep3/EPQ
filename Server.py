#Imports
import json
import socket
import base64
import logging
import colorlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12345

#Logging setup
logFormatter = colorlog.ColoredFormatter(
            "%(log_color)s%(levelname)s: %(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )

consoleLogHandler = logging.StreamHandler()
consoleLogHandler.setFormatter(logFormatter)
consoleLogHandler.setLevel(logging.DEBUG)

# General handler
with open(f"ServerGeneral.log", "w") as f:
    f.write("") #Clearing file
generalLogHandler = logging.FileHandler(f"ServerGeneral.log")
generalLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
generalLogHandler.setLevel(logging.DEBUG) 

#Error handler
with open(f"ServerErrors.log", "w") as f:
    f.write("")
errorLogHandler = logging.FileHandler(f"ServerErrors.log")
errorLogHandler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
errorLogHandler.setLevel(logging.ERROR)  

#Creating logger
logger = logging.getLogger("colorLogger")
logger.setLevel(logging.DEBUG)

# Adding handlers to the logger
logger.addHandler(consoleLogHandler) 
logger.addHandler(generalLogHandler)    
logger.addHandler(errorLogHandler) 

#Keypair generation
privateKey = ec.generate_private_key(ec.SECP256R1())
publicKey = privateKey.public_key()

pemPrivate = privateKey.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  
    #NTS : Later "decide" to use password with BestAvailableEncryption for security
)
with open("ServerECCPrivateKey.pem", "wb") as f:
    f.write(pemPrivate)
    
pemPublic = publicKey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("ServerECCPublicKey.pem", "wb") as f:
    f.write(pemPublic)

#Listening for information
incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
incomingConnectionSocket.listen(5)

logger.info("WAITING FOR REQUESTS")
clientSocket, addr = incomingConnectionSocket.accept()
receivedMessage = json.loads(clientSocket.recv(512).rstrip(b"\0").decode())
logger.info(f"MESSAGE FROM {addr} : {receivedMessage}")

def CreateEphemeralECCKey():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    return privateEphemeralKey, publicEphemeralKey

privateEphemeralKey, publicEphemeralKey = CreateEphemeralECCKey()

privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

ephemeralKeyData = json.dumps({"Type" : "Client-Server Ephemeral Key Transmission Response", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
clientSocket.send(ephemeralKeyData.encode().ljust(512, b"\0"))

#Creating the shared secret
clientEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(), 
    base64.b64decode(receivedMessage["publicEphemeralKey"])
)
ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), clientEphemeralPublicKey)
logger.warning(f"(TO DELETE) Ephemeral Secret: {ephemeralSecret.hex()}")

#Deriving an AES key
clientAESKey = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"Client-Server Handshake",
).derive(ephemeralSecret)

#Receiving the dummy attempt login
aes = AESGCM(clientAESKey)
receivedMessage = json.loads(clientSocket.recv(512).rstrip(b"\0").decode())
loginNonce = base64.b64decode(receivedMessage["Nonce"])
logger.debug(f"Username : {aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Username"]), None).decode()}, Password : {aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Password"]), None).decode()}")
logger.debug(f"Username Raw : {base64.b64decode(receivedMessage["Username"]).hex()}")