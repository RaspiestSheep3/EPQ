from PIL import Image
from pathlib import Path
import random

scriptFolder = Path(__file__).parent 
getPath = scriptFolder / 'TestImage.png'
savePath = scriptFolder / 'TestImageStego.png'
grayscaleSavePath = scriptFolder / 'TestImageRaw.png'

# Image dimensions
width = 256
height = 256

img = Image.open(getPath)
imgRawGrayscale = Image.new("L", (width, height), color=(255))
imgOut = Image.new("L", (width, height), color=(255))

print(img.mode)
if(img.mode == "RGB" or img.mode == "RGBA"):
    for x in range(width):
        for y in range(height):
            R,G,B, _ = img.getpixel((x,y))
            cell = int(0.299 * R + 0.587 * G + 0.114 * B)
            imgOut.putpixel((x,y), cell)
            imgRawGrayscale.putpixel((x,y), cell)
elif(img.mode == "L"):
    for x in range(width):
        for y in range(height):
            cell = img.getpixel((x,y))
            imgOut.putpixel((x,y), cell)
            imgRawGrayscale.putpixel((x,y), cell)
else:
    img = img.convert("RGB")
    for x in range(width):
        for y in range(height):
            R,G,B = img.getpixel((x,y))
            cell = int(0.299 * R + 0.587 * G + 0.114 * B)
            imgOut.putpixel((x,y), cell)
            imgRawGrayscale.putpixel((x,y), cell)

imgRawGrayscale.save(grayscaleSavePath)

#Embedding data
with open(r"EPQ\Steganalysis\DataToEmbed.txt", "r") as fileHandle:
    dataToEmbed = fileHandle.read(int(input("amount of data to embed : ") ) // 8).encode("ascii")

bitListToEmbed = []

for byte in dataToEmbed:
    bits = format(byte, "08b")
    for bit in bits:
        bitListToEmbed.append(int(bit == "1"))

print(len(bitListToEmbed))

#* This is when we go in a set order from the start
def EmbedLexicographically():
    counter = 0
    for x in range(width):
        for y in range(height):
            L = imgOut.getpixel((x,y))
            if(counter == len(bitListToEmbed)):
                print("Broken out")
                break
            
            if(bitListToEmbed[counter] == 1):
                L= L | 1
            else:
                L = L & ~1
            imgOut.putpixel((x,y), L)
            counter += 1
        if(counter == len(bitListToEmbed)):
            print("Broken out")
            break
    print(x, y)
    imgOut.save(savePath)

#* In practice this would be done with a pseudorandom generator or some similar method, but I am using random for testing purposes
def EmbedRandomly():
    counter = 0
    targetedCoordinates = []
    while(len(targetedCoordinates) < (width * height)) and (counter < len(bitListToEmbed)):
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        while((x,y) in targetedCoordinates):
            x = random.randint(0, width - 1)
            y = random.randint(0, height - 1)
        
        L = imgOut.getpixel((x,y))
        if(counter == len(bitListToEmbed)):
            print("Broken out")
            break
        
        if(bitListToEmbed[counter] == 1):
            L= L | 1
        else:
            L = L & ~1
        imgOut.putpixel((x,y), L)
        counter += 1
        
    imgOut.save(savePath)
    print("Done")

userInput = input("L(exicographical) or (R)andom ? : ").upper()
if(userInput == "L"):
    EmbedLexicographically()
elif(userInput == "R"):
    EmbedRandomly()     