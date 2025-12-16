#Imports
import os
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
INCOMING_CONNECTION_HOST = "127.0.0.1"
INCOMING_CONNECTION_PORT = 12346
SERVER_CONNECTION_PORT = 12345

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
serverSocket, aes = None, None
privateKey, publicKey, privateKeyBytes, publicKeyBytes = None, None, None, None
username = None
running = True

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
        )
        with open("ClientECCPrivateKey.pem", "wb") as f:
            f.write(pemPrivate)
            
        pemPublic = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("ClientECCPublicKey.pem", "wb") as f:
            f.write(pemPublic)
            
        privateKeyBytes = privateKey.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        
        publicKeyBytes = publicKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )    
        
        return privateKey, publicKey, privateKeyBytes, publicKeyBytes
    except Exception as e:
        logger.error(f"Error {e} in CreateECCKeypair", exc_info=True)

#Setting up a connection to the server
def ConnectToServer(privateEphemeralKey, publicEphemeralKeyBytes): 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect(("127.0.0.1", SERVER_CONNECTION_PORT))
        
        ephemeralKeyData = json.dumps({"Type" : "Client-Server Ephemeral Key Transmission", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
        serverSocket.send(ephemeralKeyData.encode().ljust(512, b"\0"))
        receivedMessage = json.loads(serverSocket.recv(512).rstrip(b"\0").decode())
        logger.debug(receivedMessage)

        #Creating the shared secret
        serverEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            base64.b64decode(receivedMessage["publicEphemeralKey"])
        )
        ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), serverEphemeralPublicKey)

        #Deriving an AES key
        serverAESKey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Client-Server Handshake",
        ).derive(ephemeralSecret)

        aes = AESGCM(serverAESKey)        
        return serverSocket, aes
    except Exception as e:
        logger.error(f"Error {e} in ConnectToServer", exc_info=True)

#Ephemeral Key Creation
def CreateEphemeralECCKeypair():
    try:
        privateEphemeralKey = ec.generate_private_key(ec.SECP256R1())
        publicEphemeralKey = privateEphemeralKey.public_key()
        
        privateEphemeralKeyBytes = privateEphemeralKey.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        
        publicEphemeralKeyBytes = publicEphemeralKey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return privateEphemeralKey, publicEphemeralKey, privateEphemeralKeyBytes, publicEphemeralKeyBytes
    except Exception as e:
        logger.error(f"Error {e} in CreateEphemeralKeypair", exc_info=True)

def QueryUsername(arguments: list):
    if(arguments[0] == username):
        print("Username same as argument : returning")
        return
    
    nonce = os.urandom(12)
    queryRequest = {
        "Type" : "Username Query Request",
        "Targeted Username" : base64.b64encode(aes.encrypt(nonce, arguments[0].encode(), None)).decode(), 
        "Nonce" : base64.b64encode(nonce).decode()
    }
    
    serverSocket.send(json.dumps(queryRequest).encode().ljust(1024, b"\0"))
    queryResponse = json.loads(serverSocket.recv(1024).rstrip(b"\0").decode())
    
    target = aes.decrypt(IncrementNonce(nonce, 1), base64.b64decode(queryResponse["Targeted Username"]), None).decode()
    targetOnline = int(aes.decrypt(IncrementNonce(nonce, 2), base64.b64decode(queryResponse["Target Online"]), None).decode())
    targetExists = int(aes.decrypt(IncrementNonce(nonce, 3), base64.b64decode(queryResponse["Target Exists"]), None).decode())

    print(f"{target} {'is online' if targetOnline == 1 else 'is offline' if targetOnline == 0 and targetExists else 'does not exist'}")

def SendLogin(arguments : list, loginType : str = "Login"):
    try:
        global username
        username = arguments[0]
        password = arguments[1]
        loginNonce = os.urandom(12)
        
        signaturePlaintext = f"{username}~{password}~{publicKeyBytes.hex()}"
        
        signature = privateKey.sign(
            signaturePlaintext.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        if(loginType == "Login"):
            attemptType = "Login Attempt"
        elif(loginType == "Signup"):
            attemptType = "Signup Attempt"
        else:
            logger.error(f"Invalid loginType in SendLogin : {loginType}")
        
        loginAttempt = json.dumps({"Type" : attemptType, 
            "Username" : base64.b64encode(aes.encrypt(loginNonce, username.encode(), None)).decode(), 
            "Password" : base64.b64encode(aes.encrypt(IncrementNonce(loginNonce, 1), password.encode(), None)).decode(), 
            "Public Key" : base64.b64encode(aes.encrypt(IncrementNonce(loginNonce, 2), publicKeyBytes, None)).decode(),
            "Nonce" : base64.b64encode(loginNonce).decode(),
            "IP" : base64.b64encode(aes.encrypt(IncrementNonce(loginNonce, 3), INCOMING_CONNECTION_HOST.encode(), None)).decode(),
            "Port" : base64.b64encode(aes.encrypt(IncrementNonce(loginNonce, 4), str(INCOMING_CONNECTION_PORT).encode(), None)).decode(),
            "Signature" : base64.b64encode(signature).decode()})
        
        serverSocket.send(loginAttempt.encode().ljust(1024, b"\0"))
        
        #Response
        loginResponseEncoded = json.loads(serverSocket.recv(1024).rstrip(b"\0").decode())
        
        if(loginType == "Login"):
            loginResponse = {
                "Result" : aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["Result"]), None).decode(),
                "UsernameExists"  : int(aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["UsernameExists"]), None).decode(), 2),
                "PasswordCorrect" : int(aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["PasswordCorrect"]), None).decode(), 2),
                "SignatureValid"  : int(aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["SignatureValid"]), None).decode(), 2),
            }
            
            print(
    f"""{"{:<10}".format("Response")} : {"Success" if loginResponse["Result"] == "Pass" else "Failure"}
    {"{:<10}".format("Username")} : {"Correct" if int(loginResponse["UsernameExists"]) == 1 else "Non-existent"}
    {"{:<10}".format("Password")} : {"Correct" if int(loginResponse["PasswordCorrect"]) == 1 else "Incorrect"}
    {"{:<10}".format("Signature")} : {"Valid" if int(loginResponse["SignatureValid"]) == 1 else "Invalid"}""")
            
        elif(loginType == "Signup"):
            loginResponse = {
                "Result" : aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["Result"]), None).decode(),
                "UsernameFree"  : int(aes.decrypt(loginNonce, base64.b64decode(loginResponseEncoded["UsernameExists"]), None).decode(), 2),
            }
            
            print(
    f"""{"{:<10}".format("Response")} : {"Success" if loginResponse["Result"] == "Pass" else "Failure"}
    {"{:<10}".format("Username")} : {"Available" if int(loginResponse["UsernameFree"]) == 1 else "Already In Use"}""")
        if(loginResponse["Result"] == "Pass"):
            return username
    except Exception as e:
        logger.debug(f"Error {e} in SendLogin", exc_info=True)

def SendQuit():
    global running
    try:
        quitNonce = os.urandom(12)
        serverSocket.send(json.dumps({
            "Type" : "Client Quit", 
            "Username" : base64.b64encode(aes.encrypt(quitNonce, username.encode(), None)).decode(),
            "Nonce" : base64.b64encode(quitNonce).decode()}).encode().ljust(1024, b"\0"))
        serverSocket.shutdown(socket.SHUT_RDWR)
        serverSocket.close()
        running = False
    except Exception as e:
        logger.error(f"Error {e} in SendQuit", exc_info=True)

def Start():
    try:
        global serverSocket, aes, privateKey, publicKey, privateKeyBytes, publicKeyBytes, username
        
        #ECC setup
        privateKey, publicKey, privateKeyBytes, publicKeyBytes = CreateECCKeypair()
        
        #Server Connection
        privateEphemeralKey, publicEphemeralKey, privateEphemeralKeyBytes, publicEphemeralKeyBytes = CreateEphemeralECCKeypair()
        serverSocket, aes = ConnectToServer(privateEphemeralKey, publicEphemeralKeyBytes)


        #Start the command listener
        while running:
            userInput = input(">>").strip()
            if(userInput[0] == "!"):
                #Its a command
                commandSplit = userInput.split(" ")
                if(commandSplit[0].lower() == "!login"):
                    username = SendLogin(commandSplit[1:])
                elif(commandSplit[0].lower() == "!signup"):
                    username = SendLogin(commandSplit[1:], "Signup")
                elif(commandSplit[0].lower() == "!quit"):
                    SendQuit()
                elif(commandSplit[0].lower() == "!query"):
                    QueryUsername(commandSplit[1:])
                else:
                    print("Command Unknown")
    except Exception as e:
        logger.error(f"Error {e} in Start", exc_info=True)

Start()