#Imports
import os
import json
import socket
import base64
import logging
import sqlite3
import colorlog
import threading
from passlib.hash import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
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

#Runtime variables
onlineUsers = dict()

def IncrementNonce(oldNonce : bytes, increment : int):
    try:
        oldNonceInt = int.from_bytes(oldNonce, byteorder="big")
        oldNonceInt = (oldNonceInt + increment) % (1 << 96) #Wraparound
        nonce = oldNonceInt.to_bytes(12, byteorder="big")
        return nonce
    except Exception as e:
        logger.error(f"Error {e} in IncrementNonce", exc_info=True)

#Keypair generation
def CreateECCKeypair():
    try:
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
    except Exception as e:
        logger.error(f"Error {e} in CreateECCKeypair", exc_info=True)

def CreateSQL():
    try:
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
    except Exception as e:
        logger.error(f"Error {e} in CreateSQL", exc_info=True)

def HandleQuery(clientSocket, receivedMessage, aes):
    try:
        nonce = base64.b64decode(receivedMessage["Nonce"])
        targetedUsername = aes.decrypt(nonce, base64.b64decode(receivedMessage["Targeted Username"]), None).decode()

        targetOnline = 1 if targetedUsername in onlineUsers else 0
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM details WHERE username = ?
        """, (targetedUsername, ))
        row = cursor.fetchone()
        targetExists = 1 if (row != None) and (row!=[]) else 0
        
        IPAddress = onlineUsers[targetedUsername]["IP"] if targetedUsername in onlineUsers else "None"
        port = onlineUsers[targetedUsername]["Port"] if targetedUsername in onlineUsers else -1
        
        
        queryResponse = {
            "Type" : "Username Query Response",
            "Targeted Username" : base64.b64encode(aes.encrypt(IncrementNonce(nonce, 1), targetedUsername.encode(), None)).decode(),  
            "Target Online" : base64.b64encode(aes.encrypt(IncrementNonce(nonce, 2), str(targetOnline).encode(), None)).decode(),  
            "Target Exists" : base64.b64encode(aes.encrypt(IncrementNonce(nonce, 3), str(targetExists).encode(), None)).decode(),  
            "IP" : base64.b64encode(aes.encrypt(IncrementNonce(nonce, 4), IPAddress.encode(), None)).decode(), 
            "Port" : base64.b64encode(aes.encrypt(IncrementNonce(nonce, 5), str(port).encode(), None)).decode()
        }
        
        clientSocket.send(json.dumps(queryResponse).encode().ljust(1024, b"\0"))
    except Exception as e:
        logger.error(f"Error {e} in HandleQuery", exc_info=True)

def HandleLogin(clientSocket, receivedMessage, aes):
    global onlineUsers
    try:
        loginNonce = base64.b64decode(receivedMessage["Nonce"])
        username = aes.decrypt(loginNonce, base64.b64decode(receivedMessage["Username"]), None).decode()
        passwordRaw = aes.decrypt(IncrementNonce(loginNonce, 1), base64.b64decode(receivedMessage["Password"]), None).decode()
        password = argon2.hash(passwordRaw)
        IPAddress = aes.decrypt(IncrementNonce(loginNonce, 3), base64.b64decode(receivedMessage["IP"]), None).decode()
        port = int(aes.decrypt(IncrementNonce(loginNonce, 4), base64.b64decode(receivedMessage["Port"]), None).decode())
        publicKeyBytes = aes.decrypt(IncrementNonce(loginNonce, 2), base64.b64decode(receivedMessage["Public Key"]), None)
        signature = base64.b64decode(receivedMessage["Signature"])
        logger.debug(f"Username : {username}, Password : {passwordRaw}")

        #SQL update
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM details WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if(receivedMessage["Type"] == "Signup Attempt"):
            #Signup SQL
            loginResponse = {"Result" : "Pass", "UsernameFree" : 1}
            
            if(row == None or len(row) == 0):
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
                loginResponse["Result"] = "Fail"
                loginResponse["UsernameFree"] = 0
            
            loginResponseEncoded = json.dumps({
                "Result" : base64.b64encode(aes.encrypt(loginNonce, loginResponse["Result"].encode(), None)).decode(), 
                "UsernameExists" : base64.b64encode(aes.encrypt(loginNonce, bin(loginResponse["UsernameFree"]).encode(), None)).decode()}).encode()
            
            clientSocket.send(loginResponseEncoded.ljust(1024, b"\0"))
        
        elif(receivedMessage["Type"] == "Login Attempt"):
            loginResponse = {"Result" : "Pass", "UsernameExists" : 1, "PasswordCorrect" : 1, "SignatureValid" : 1}
            
            if(row == None or len(row) == 0):
                #Entry does not exist
                logger.warning(f"Username {username} is not in database")
                loginResponse["Result"] = "Fail"
                loginResponse["UsernameExists"] = 0
            else:
                #Entry already exists
                logger.debug(f"row : {row}")
                
                if(not argon2.verify(passwordRaw, row[1])):
                    loginResponse["Result"] = "Fail"
                    loginResponse["PasswordCorrect"] = 0

                clientPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), 
                    publicKeyBytes
                )
                try:
                    clientPublicKey.verify(
                        signature,
                        f"{username}~{passwordRaw}~{publicKeyBytes.hex()}".encode(),
                        ec.ECDSA(hashes.SHA256())
                    )
                    
                    logger.debug("Signature correct")
                    
                except InvalidSignature:
                    logger.warning("Signature invalid")
                    loginResponse["Result"] = "Fail"
                    loginResponse["SignatureValid"] = 0
            
            loginResponseEncoded = json.dumps({
                "Result" : base64.b64encode(aes.encrypt(loginNonce, loginResponse["Result"].encode(), None)).decode(), 
                "UsernameExists"  : base64.b64encode(aes.encrypt(loginNonce, bin(loginResponse["UsernameExists"]).encode(), None)).decode(), 
                "PasswordCorrect" : base64.b64encode(aes.encrypt(loginNonce, bin(loginResponse["PasswordCorrect"]).encode(), None)).decode(), 
                "SignatureValid"  : base64.b64encode(aes.encrypt(loginNonce, bin(loginResponse["SignatureValid"]).encode(), None)).decode()}).encode()
            
            clientSocket.send(loginResponseEncoded.ljust(1024, b"\0"))
                    
        else:
            logger.warning(f"Type {receivedMessage["Type"]} unknown")
        
        conn.close()
        
        if(loginResponse["Result"] == "Pass"):
            #They are now an online user
            onlineUsers[username] = {"IP" : IPAddress, "Port" : port}
            logger.debug(f"New Online Users : {onlineUsers}")

        return username
    except Exception as e:
        logger.error(f"Error {e} in HandleLogin", exc_info=True)

def HandleQuit(clientSocket, receivedMessage, aes):
    try:
        nonce =  base64.b64decode(receivedMessage["Nonce"])
        username = aes.decrypt(nonce, base64.b64decode(receivedMessage["Username"]), None).decode()
        logger.debug(f"User {username} has quit")
        clientSocket.shutdown(socket.SHUT_WR)
        clientSocket.close()
        onlineUsers.pop(username)
        return False
    except Exception as e:
        logger.error(f"Error {e} in HandleQuit", exc_info=True)

def HandleClient(clientSocket):
    global onlineUsers
    try:
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
        aes = AESGCM(clientAESKey)
        
        #Receiving requests
        clientRunning = True
        while clientRunning:
            receivedMessage = json.loads(clientSocket.recv(1024).rstrip(b"\0").decode())
            if(receivedMessage["Type"] in ["Login Attempt", "Signup Attempt"]):
                username = HandleLogin(clientSocket, receivedMessage, aes)
            elif(receivedMessage["Type"] == "Client Quit"):
                clientRunning = HandleQuit(clientSocket, receivedMessage, aes)
            elif(receivedMessage["Type"] == "Username Query Request"):
                HandleQuery(clientSocket, receivedMessage, aes)
    except ConnectionResetError:
        logger.debug("Received ConnectionAbortedError : removing from onlineUsers")
        onlineUsers.pop(username)
    except Exception as e:
        logger.error(f"Error {e} in HandleClient", exc_info=True)

def CreateEphemeralECCKey():
    try:
        privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
        publicEphemeralKey = privateEphemeralKey.public_key()
        
        return privateEphemeralKey, publicEphemeralKey
    except Exception as e:
        logger.error(f"Error {e} in CreateEphemeralECCKey", exc_info=True)

def Start():
    try:
        CreateSQL()
        
        #Listening for information
        incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
        incomingConnectionSocket.listen(5)

        logger.info("WAITING FOR REQUESTS")
        while True:
            clientSocket, addr = incomingConnectionSocket.accept()
            threading.Thread(target=HandleClient, args=(clientSocket,)).start()
    except Exception as e:
        logger.error(f"Error {e} in Start", exc_info=True)

Start()