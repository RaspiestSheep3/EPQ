#Imports
import os
import json
import socket
import base64
import logging
import sqlite3
import colorlog
from passlib.hash import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "0.0.0.0"
INCOMING_CONNECTION_PORT = 12345
DATABASE_NAME = "ServerDatabase.db"

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
def CreateECCKeypair():
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

def CreateSQL():
    if(not os.path.exists(DATABASE_NAME)):
        logger.warning("Server Database does not exist - creating new database")
    
    conn = sqlite3.connect(DATABASE_NAME) #This autocreates the database if it does not exist
    cursor = conn.cursor()
    
    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS details (
    username TEXT PRIMARY KEY,
    password BLOB NOT NULL,
    publicKey BLOB NOT NULL UNIQUE)
    """)
    
    conn.commit()
    conn.close()
    logger.debug("Created SQL database and 'details' table")
    
def Start():
    CreateSQL()
    
    #Listening for information
    incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
    incomingConnectionSocket.listen(5)

    logger.info("WAITING FOR REQUESTS")
    clientSocket, addr = incomingConnectionSocket.accept()
    HandleClient(clientSocket)

def HandleClient(clientSocket):
    receivedMessage = json.loads(clientSocket.recv(512).rstrip(b"\0").decode())
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

    #Deriving an AES key
    clientAESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Client-Server Handshake",
    ).derive(ephemeralSecret)
    
    #Receiving the dummy attempt login
    aes = AESGCM(clientAESKey)
    receivedMessage = json.loads(clientSocket.recv(1024).rstrip(b"\0").decode())
    loginNonce = base64.b64decode(receivedMessage["Nonce"])
    username = aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Username"]), None).decode()
    passwordRaw = aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Password"]), None).decode()
    password = argon2.hash(passwordRaw)
    publicKeyBytes = aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Public Key"]), None).decode()
    logger.debug(f"Username : {username}, Password : {passwordRaw}")

    #SQL update
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM details WHERE username = ?", (username,))
    rows = cursor.fetchall()
    
    if(len(rows) == 0):
        #Entry does not exist
        logger.debug(f"Username {username} is not in database")
        cursor.execute("""
        INSERT INTO details (
            username, password, publicKey
        ) VALUES (?, ?, ?)
        """, (username, password, publicKeyBytes))
        conn.commit()
        
        logger.warning(f"(TO DELETE) hash : {password}, verification : {argon2.verify(passwordRaw, password)}")
    else:
        #Entry already exists
        logger.warning(f"Username {username} is already in the database")
    
    conn.close()

def CreateEphemeralECCKey():
    privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
    publicEphemeralKey = privateEphemeralKey.public_key()
    
    return privateEphemeralKey, publicEphemeralKey

Start()