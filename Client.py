#Imports
import os
import hmac
import json
import queue
import socket
import base64
import hashlib
import logging
import sqlite3
import colorlog
import threading
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Constants
INCOMING_CONNECTION_HOST = "127.0.0.1"
INCOMING_CONNECTION_PORT = int(input("Port : "))
SERVER_CONNECTION_PORT = 12345
IMAGE_FOLDER_PATH = r"EPQ\Research\Test Images"

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
setChat = None
chatQueues = dict()

class HMAC_DRBG:
    def __init__(self, seed: bytes):
        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self._update(seed)

    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, seed=b""):
        self.K = self._hmac(self.K, self.V + b"\x00" + seed)
        self.V = self._hmac(self.K, self.V)
        if seed:
            self.K = self._hmac(self.K, self.V + b"\x01" + seed)
            self.V = self._hmac(self.K, self.V)

    def randbytes(self, n):
        output = b""
        while len(output) < n:
            self.V = self._hmac(self.K, self.V)
            output += self.V
        self._update()
        return output[:n]

    def randint(self, maxExclusive):
        raw = self.randbytes(4)
        return int.from_bytes(raw, "big") % maxExclusive

def EmbedToImage(secret, embedDRBG):
    try:
        #Picking a random image from the database list
        setupDRBG = HMAC_DRBG(os.urandom(32))
        availableImages = os.listdir(IMAGE_FOLDER_PATH)
        chosenImagePath = availableImages[setupDRBG.randint(0, len(availableImages))]
        
        #Loading the image in PIL
        stego = Image.open(str(os.path.join(IMAGE_FOLDER_PATH, chosenImagePath)))
        
        #Working out how much noise to apply
        totalLSBPlanePixels = 256 ** 2
        secretLength = len(secret) * 8
        noiseAmount = int(totalLSBPlanePixels * 0.25) - secretLength #This should lead to our total 25% goal
        
        targetedPixels = set()
        
        #Creating the binary list for embedding
        embedList = []
        secretEncoded = secret.encode("ascii")
        for byte in secretEncoded:
            bits = format(byte, "08b")
            for bit in bits:
                embedList.append(int(bit == "1"))
        
        for i in range(len(embedList)):
            point = (None, None)
            while(point == (None, None) or point in targetedPixels):
                point = (embedDRBG.randint(0,256), embedDRBG.randint(0,256))
            
            pixelValue = stego.getpixel(point)
            pixelValueNew = (pixelValue // 2) * 2 + embedList[i]
            stego.putpixel(point, pixelValueNew) 
            
            targetedPixels.add(point)
        
        #Applying noise
        for i in range(noiseAmount):
            point = (None, None)
            while(point == (None, None) or point in targetedPixels):
                point = (setupDRBG.randint(0,256), setupDRBG.randint(0,256))
            
            pixelValue = stego.getpixel(point)
            pixelValueNew = (pixelValue // 2) * 2 + setupDRBG.randint(0,2)
            stego.putpixel(point, pixelValueNew) 
            
            targetedPixels.add(point)
        
        return stego
    except Exception as e:
        logger.error(f"Error {e} in EmbedToImage", exc_info=True)
    

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
        if(not os.path.exists(f"ClientECC{username}PrivateKey.pem")):
            privateKey = ec.generate_private_key(ec.SECP256R1())
            publicKey = privateKey.public_key()

            pemPrivate = privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  
            )
            with open(f"ClientECC{username}PrivateKey.pem", "wb") as f:
                f.write(pemPrivate)
                
            pemPublic = publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(f"ClientECC{username}PublicKey.pem", "wb") as f:
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
        
        else:
            with open(f"ClientECC{username}PrivateKey.pem", "rb") as f:
                privateKey = serialization.load_pem_private_key(
                    f.read(),
                    password=None 
                )
                
            with open(f"ClientECC{username}PublicKey.pem", "rb") as f:
                publicKey = serialization.load_pem_public_key(f.read())
            
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
    try:
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

        IPAddress = aes.decrypt(IncrementNonce(nonce, 4), base64.b64decode(queryResponse["IP"]), None).decode()
        Port = aes.decrypt(IncrementNonce(nonce, 5), base64.b64decode(queryResponse["Port"]), None).decode()
        
        publicKeyBytes = aes.decrypt(IncrementNonce(nonce, 6), base64.b64decode(queryResponse["Public Key"]), None)
        
        return targetOnline, targetExists, (IPAddress, Port), publicKeyBytes
    except Exception as e:
        logger.error(f"Error {e} in QueryUsername")
    
def StarUser(arguments : list):
    try:
        if(arguments[0] == username):
            print("Username same as argument : returning")
            return

        #Checking the user actually exists
        _, targetExists, _, _ = QueryUsername(arguments)
        
        if(targetExists == 0):
            return
        
        conn = sqlite3.connect(f"{username}Database.db")
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR IGNORE INTO starredUsernames (
            username
        ) VALUES (?)
        """, (arguments[0],))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error {e} in StarUser")
 
def QueryStarred():
    global username
    try:
        conn = sqlite3.connect(f"{username}Database.db")
        cursor = conn.cursor()
        cursor.execute("""SELECT * FROM starredUsernames""")
        rows = cursor.fetchall()
        print("Starred Users : ")
        for starredUsername in rows:
            QueryUsername([starredUsername[0]])
    except Exception as e:
        logger.error(f"Error {e} in QueryStarred", exc_info=True)
    
def UnstarUser(arguments):
    try:
        conn = sqlite3.connect(f"{username}Database.db")
        cursor = conn.cursor()
        cursor.execute("""DELETE FROM starredUsernames where username = ?""", (arguments[0],))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error {e} in UnstarUser")
    
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
            
            #Setting up the database
            conn = sqlite3.connect(f"{username}Database.db")
            cursor = conn.cursor()
            cursor.execute(f""" 
            CREATE TABLE IF NOT EXISTS starredUsernames (
            username TEXT PRIMARY KEY)""")
            conn.commit()
            conn.close()
            
            QueryStarred()
            
    except Exception as e:
        logger.error(f"Error {e} in SendLogin", exc_info=True)

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

def ConnectToPeer(arguments):
    userOnline, _, (IPAddress, port), otherPublicKeyBytes = QueryUsername(arguments)
    
    if(userOnline == 0):
        return
    
    logger.debug(f"IP : {IPAddress}, Port : {port}")

    #Creating the connection to the other client
    peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peerSocket.connect((IPAddress, int(port)))
    threading.Thread(target=HandlePeer, args=(peerSocket,True, otherPublicKeyBytes, arguments[0])).start()

def HandlePeer(peerSocket, sender, otherPublicKeyBytes, otherUsername=None):
    global setChat
    #Deriving an AES key we can use
    privateEphemeralKey, _, _, publicEphemeralKeyBytes = CreateEphemeralECCKeypair()

    ephemeralKeyData = json.dumps({"Type" : "P2P Ephemeral Key Transmission", "publicEphemeralKey" : base64.b64encode(publicEphemeralKeyBytes).decode()})
    
    #Doing this to stop issues wehre both send simultaenously
    if(sender):
        peerSocket.send(ephemeralKeyData.encode().ljust(1024, b"\0"))
        receivedMessage = json.loads(peerSocket.recv(1024).rstrip(b"\0").decode())
        logger.debug(receivedMessage)
    else:
        receivedMessage = json.loads(peerSocket.recv(1024).rstrip(b"\0").decode())
        peerSocket.send(ephemeralKeyData.encode().ljust(1024, b"\0"))
        logger.debug(receivedMessage)

    #Creating the shared secret
    peerEphemeralPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), 
        base64.b64decode(receivedMessage["publicEphemeralKey"])
    )
    ephemeralSecret = privateEphemeralKey.exchange(ec.ECDH(), peerEphemeralPublicKey)

    #Deriving an AES key
    P2PAESKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"P2P Handshake",
    ).derive(ephemeralSecret)
    
    HMAC_DRBGKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"P2P Steganography",
    ).derive(ephemeralSecret)
    dbrg = HMAC_DRBG(HMAC_DRBGKey)

    peerAES = AESGCM(P2PAESKey)
    
    #Sending an introduction
    
    logger.debug(f"Username : {username}")
    
    if(sender):
        peerNonce = os.urandom(12)
        signature = privateKey.sign(
            publicEphemeralKeyBytes + base64.b64decode(receivedMessage["publicEphemeralKey"]),
            ec.ECDSA(hashes.SHA256())
        )
        
        logger.debug(f"Signature : {signature.hex()}")
        logger.debug(f"Addition : {(base64.b64decode(receivedMessage["publicEphemeralKey"]) + publicEphemeralKeyBytes).hex()}")
        logger.debug(f"Public key : {publicKeyBytes.hex()}")
        
        introduction = {"Nonce" : base64.b64encode(peerNonce).decode(), "Username" : base64.b64encode(peerAES.encrypt(peerNonce, username.encode(), None)).decode(), "Signature" : base64.b64encode(peerAES.encrypt(IncrementNonce(peerNonce, 1), signature,None)).decode()}
        
        peerSocket.send(json.dumps(introduction).encode().ljust(1024, b"\0"))
        introductionResponse = json.loads(peerSocket.recv(1024).rstrip(b"\0").decode())

        #Checking the signature
        peerPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            otherPublicKeyBytes
        )
        
        try:
            peerPublicKey.verify(
                peerAES.decrypt(IncrementNonce(peerNonce, 3), base64.b64decode(introductionResponse["Signature"]), None),
                base64.b64decode(receivedMessage["publicEphemeralKey"]) + publicEphemeralKeyBytes,
                ec.ECDSA(hashes.SHA256())
            )
        
            logger.debug("Signature correct")
        
        except InvalidSignature:
            logger.warning("Signature invalid")
            return
        
        setChat = otherUsername
    else:
        introduction = json.loads(peerSocket.recv(1024).rstrip(b"\0").decode())
        peerNonce = base64.b64decode(introduction["Nonce"])
        
        otherUsername = peerAES.decrypt(peerNonce, base64.b64decode(introduction["Username"]), None).decode()
        
        _, _, _, otherPublicKeyBytes = QueryUsername([otherUsername])
        
        #Checking the signature
        peerPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            otherPublicKeyBytes
        )
        
        logger.debug(f"Other Username : {peerAES.decrypt(peerNonce, base64.b64decode(introduction["Username"]), None).decode()}")
        logger.debug(f"Signature : {peerAES.decrypt(IncrementNonce(peerNonce, 1), base64.b64decode(introduction["Signature"]), None).hex()}")
        logger.debug(f"Addition : {(base64.b64decode(receivedMessage["publicEphemeralKey"]) + publicEphemeralKeyBytes).hex()}")
        logger.debug(f"Public key : {otherPublicKeyBytes.hex()}")
        
        try:
            peerPublicKey.verify(
                peerAES.decrypt(IncrementNonce(peerNonce, 1), base64.b64decode(introduction["Signature"]), None),
                base64.b64decode(receivedMessage["publicEphemeralKey"]) + publicEphemeralKeyBytes,
                ec.ECDSA(hashes.SHA256())
            )
        
            logger.debug("Signature correct")
        
        except InvalidSignature:
            logger.warning("Signature invalid")
            return
        
        signature = privateKey.sign(
                publicEphemeralKeyBytes + base64.b64decode(receivedMessage["publicEphemeralKey"]),
                ec.ECDSA(hashes.SHA256())
            )
        introductionResponse = {"Username" : base64.b64encode(peerAES.encrypt(IncrementNonce(peerNonce, 2), username.encode(), None)).decode(), "Signature" : base64.b64encode(peerAES.encrypt(IncrementNonce(peerNonce, 3), signature,None)).decode()}
        
        peerSocket.send(json.dumps(introductionResponse).encode().ljust(1024, b"\0"))
    
    chatQueues[otherUsername] = {"Sender Queue" : queue.Queue(), "Receiver Queue" : queue.Queue()}
    
def ListenerHandler():
    incomingConnectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingConnectionSocket.bind((INCOMING_CONNECTION_HOST, INCOMING_CONNECTION_PORT))
    incomingConnectionSocket.listen(5)
    
    while True:
            peerSocket, addr = incomingConnectionSocket.accept()
            threading.Thread(target=HandlePeer, args=(peerSocket,False, None)).start()

def Start():
    try:
        global username, serverSocket, aes, privateKey, publicKey, privateKeyBytes, publicKeyBytes, username, setChat
        
        #ECC setup
        username = input("Key Username : ")
        privateKey, publicKey, privateKeyBytes, publicKeyBytes = CreateECCKeypair()
        
        #Server Connection
        privateEphemeralKey, publicEphemeralKey, privateEphemeralKeyBytes, publicEphemeralKeyBytes = CreateEphemeralECCKeypair()
        serverSocket, aes = ConnectToServer(privateEphemeralKey, publicEphemeralKeyBytes)

        #Starting a peer listener
        threading.Thread(target=ListenerHandler, daemon=True).start()

        #Start the command listener
        while running:
            userInput = input(">>").strip()
            if(userInput[0] == "!"):
                #Its a command
                commandSplit = userInput.split(" ")
                if(commandSplit[0].lower() == "!login"):
                    SendLogin(commandSplit[1:])
                elif(commandSplit[0].lower() == "!signup"):
                    SendLogin(commandSplit[1:], "Signup")
                elif(commandSplit[0].lower() == "!quit"):
                    SendQuit()
                elif(commandSplit[0].lower() == "!query"):
                    QueryUsername(commandSplit[1:])
                elif(commandSplit[0].lower() == "!star"):
                    StarUser(commandSplit[1:])
                elif(commandSplit[0].lower() == "!querystarred"):
                    QueryStarred()
                elif(commandSplit[0].lower() == "!unstar"):
                    UnstarUser(commandSplit[1:])
                elif(commandSplit[0].lower() == "!connect"):
                    threading.Thread(target = ConnectToPeer, args = (commandSplit[1:],)).start()
                elif(commandSplit[0].lower() == "!setchat"):
                    setChat = commandSplit[1]
                else:
                    print("Command Unknown")
            else:
                chatQueues[setChat]["Sender Queue"].put(userInput)
    except Exception as e:
        logger.error(f"Error {e} in Start", exc_info=True)

Start()