from PIL import Image
from pathlib import Path

scriptFolder = Path(__file__).parent 
stegoPath = scriptFolder / 'TestImageStego.png'
rawPath = scriptFolder / 'TestImage.png'
bitPlaneFolder = scriptFolder / 'Bit Planes'


# Image dimensions
width = 256
height = 256
chunkSize = 32

stego = Image.open(stegoPath)
raw = Image.open(rawPath)

stegoBitPlanes = []
rawBitPlanes = []

def value_to_rgb(dfValue: float) -> tuple[int, int, int]:
    if dfValue <= 0.5:
        # interpolate between blue and green
        t = dfValue / 0.5
        r = int(0 * (1 - t) + 0 * t)
        g = int(0 * (1 - t) + 255 * t)
        b = int(128 * (1 - t) + 0 * t)
    else:
        # interpolate between green and red
        t = (dfValue - 0.5) / 0.5
        r = int(0 * (1 - t) + 255 * t)
        g = int(255 * (1 - t) + 0 * t)
        b = int(0 * (1 - t) + 0 * t)
    return (r, g, b)

for i in range(8):
    stegoBitPlane = Image.new("L", (width, height), color=(255))
    stegoBitPlanes.append(stegoBitPlane)
    
    rawBitPlane = Image.new("L", (width, height), color=(255))
    rawBitPlanes.append(rawBitPlane)

for x in range(width):
    for y in range(height):
        stegoCell = stego.getpixel((x,y))
        rawCell = raw.getpixel((x,y))
        
        bitsStego = [(stegoCell >> i) & 1 for i in range(8)]
        bitsRaw = [(rawCell >> i) & 1 for i in range(8)]
        
        #print(f"STEGO {bitsStego} RAW {bitsRaw} cell {stegoCell} {rawCell}")
        
        for i in range(8):
            #Updating each bit plane
            stegoBitPlanes[i].putpixel((x,y), bitsStego[i] * 255)
            rawBitPlanes[i].putpixel((x,y), bitsRaw[i] * 255)

    print(f"{x}/{width}, {y}/{height}")
    
for i in range(8):
    stegoBitPlanes[i].save(bitPlaneFolder / "Stego" / f"StegoBitPlane{8-i}.png")
    rawBitPlanes[i].save(bitPlaneFolder / "Raw" / f"RawBitPlane{8-i}.png")
    
shouldGenerateColourMap = input("Generate Colour Map? : ").lower() == "y"
if(shouldGenerateColourMap):
    #Stego
    with open(r"EPQ\Steganalysis\ChiSquareStego.csv") as fileHandle:
        lines = fileHandle.readlines()
        stegoData = [[int(stegoSplit[0]), float(stegoSplit[1])] for stegoSplit in [line.split(",") for line in lines]]
    
    with open(r"EPQ\Steganalysis\ChiSquareRaw.csv") as fileHandle:
        lines = fileHandle.readlines()
        rawData = [[int(rawSplit[0]), float(rawSplit[1])] for rawSplit in [line.split(",") for line in lines]]
    
    #print(stegoData)
    print(rawData)
    
    stegoLSBPlane = stegoBitPlanes[0]
    rawLSBPlane = rawBitPlanes[0]
    
    widthOffset = 0
    heightOffset = 0
    chunkCounter = 0

    stegoBitPlaneColoured = Image.new("RGB", (width, height), color=(0, 0, 0))
    rawBitPlaneColoured = Image.new("RGB", (width, height), color=(0, 0, 0))

    #Colouring stego
    for xBig in range((width // chunkSize)):
        for yBig in range((height // chunkSize)):
            heightOffset = chunkSize * yBig
            widthOffset = chunkSize * xBig
            
            dfValue = stegoData[chunkCounter][1]
            print(f"DF VALUE {dfValue}")
            r, g, b = value_to_rgb(float(dfValue))
            rgb = (int(r), int(g), int(b))
            print(rgb)
            
            for x in range(widthOffset, chunkSize + widthOffset):
                for y in range(heightOffset, chunkSize + heightOffset):
                    try:
                        L = stegoLSBPlane.getpixel((x,y))
                    except:
                        print(x,y)
                        raise ValueError
                    
                    if(L != 0):
                        stegoBitPlaneColoured.putpixel((x,y), rgb)


                    L = rawLSBPlane.getpixel((x,y))
                    if(L != 0):
                        rawBitPlaneColoured.putpixel((x,y), rgb)

            chunkCounter += 1
    
    stegoBitPlaneColoured.save(bitPlaneFolder / "Stego" / "StegoColourMap.png")
    rawBitPlaneColoured.save(bitPlaneFolder / "Raw" / "RawColourMap.png")
    
print("Done")