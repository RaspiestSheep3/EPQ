from PIL import Image
from pathlib import Path
from copy import deepcopy
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

scriptFolder = Path(__file__).parent 
stegoPath = scriptFolder / 'TestImageStego.png'
rawPath = scriptFolder / 'TestImage.png'

# Settings
width = 256
height = 256
blockSize = 8
roundAmount = 0.01
roundFormat = "{:.2f}"
#imageName = input("Image Name : ")
complexityCutoff = "{:.2f}".format(float(input("Complexity Cutoff : ")))

def GrayToBinary(gray):
    """binary = gray 
    while gray > 0: 
        gray >>= 1 
        binary ^= gray 
    return binary"""
    return gray

def BinaryToGray(binary):
    """shift = binary >> 1
    cgc = binary ^ shift
    
    return cgc"""
    return binary

def FindComplexity(block):
    N = 8
    transitions = 0

    # Horizontal transitions (row-wise)
    for row in block:
        for i in range(N - 1):
            if row[i] != row[i + 1]:
                transitions += 1

    # Vertical transitions (column-wise)
    for i in range(N - 1):
        for j in range(N):
            if block[i][j] != block[i + 1][j]:
                transitions += 1

    complexity = transitions / (2 * N * (N - 1))
    return complexity

rawBitPlaneComplexityCount = [{x/100 : 0 for x in range(1, 101)} for _ in range(8)]
stegoBitPlaneComplexityCount = [{x/100 : 0 for x in range(1, 101)} for _ in range(8)]

stego = Image.open(stegoPath)
stego = stego.convert("L")
raw = Image.open(rawPath)
raw = raw.convert("L")

for i in range(width // blockSize):
    for j in range(height // blockSize):
        stegoBlock = [[BinaryToGray(stego.getpixel((i*8 + y,j*8 + x))) for y in range(8)] for x in range(8)]
        rawBlock = [[BinaryToGray(raw.getpixel((i*8 + y,j*8 + x))) for y in range(8)] for x in range(8)]
        
        for plane in range(7, -1, -1):
            
            
            stegoBlockPlaned = deepcopy(stegoBlock)
            rawBlockPlaned = deepcopy(rawBlock)
            
            stegoBlockPlaned = [[(stegoBlockPlaned[y][x] >> plane) & 1 for x in range(8)] for y in range(8)]
            rawBlockPlaned = [[(rawBlockPlaned[y][x] >> plane) & 1 for x in range(8)] for y in range(8)]
            
            stegoBlockComplexityUnrounded = FindComplexity(stegoBlockPlaned)
            rawBlockComplexityUnrounded = FindComplexity(rawBlockPlaned)
            
            stegoBlockComplexity = round(stegoBlockComplexityUnrounded / roundAmount) * roundAmount
            rawBlockComplexity = round(rawBlockComplexityUnrounded / roundAmount) * roundAmount

            #print(f"Stego : {stegoBlockComplexity}, Raw : {rawBlockComplexity}")
            
            if(stegoBlockComplexity > 0):
                stegoBitPlaneComplexityCount[plane][float(roundFormat.format(stegoBlockComplexity))] += 1
            
            if(rawBlockComplexity > 0):
                rawBitPlaneComplexityCount[plane][float(roundFormat.format(rawBlockComplexity))] += 1

#print(f"Raw     : {dict(sorted(rawBitPlaneComplexityCount[0].items()))}")
#print(f"Stego   : {dict(sorted(stegoBitPlaneComplexityCount[0].items()))}")

colours = ["red", "blue", "green", "orange", "purple", "pink", "gray", "black"]

"""for yAxis in rawBitPlaneComplexityCount:
    #print(yAxis)
    
    print(yAxis)
    
    plt.plot(list(rawBitPlaneComplexityCount[0].keys()),list(yAxis.values()), label=(f"Bit Plane {7-rawBitPlaneComplexityCount.index(yAxis)}"), color=colours[7-rawBitPlaneComplexityCount.index(yAxis)], linewidth=2)
    
plt.xlabel("Complexity Value")
ax = plt.gca()
ax.xaxis.set_major_locator(MaxNLocator(nbins=20))  
ax.yaxis.set_major_locator(MaxNLocator(nbins=20))  
plt.ylabel("No. of blocks")
plt.legend()
plt.grid()
plt.xlim(0, 1)
plt.title(f"No. of Blocks With A Complexity == Given Complexity Value - {imageName} - Cover Image")
plt.show()

for yAxis in stegoBitPlaneComplexityCount:
    #print(yAxis)
    
    print(yAxis)
    
    plt.plot(list(stegoBitPlaneComplexityCount[0].keys()),list(yAxis.values()), label=(f"Bit Plane {7-stegoBitPlaneComplexityCount.index(yAxis)}"), color=colours[7-stegoBitPlaneComplexityCount.index(yAxis)], linewidth=2)
    
plt.title(f"No. of Blocks With A Complexity == Given Complexity Value - {imageName} - Stego Image - Complexity Cutoff Of {complexityCutoff}")
plt.xlabel("Complexity Value")
ax = plt.gca()
ax.xaxis.set_major_locator(MaxNLocator(nbins=20))  
ax.yaxis.set_major_locator(MaxNLocator(nbins=20))  
plt.ylabel("No. of blocks")
plt.legend()
plt.grid()
plt.xlim(0, 1)
plt.show()"""


for plane in range(8):
    
    """if(plane == 0 or plane==7):
        continue """
    
    xVals = list(rawBitPlaneComplexityCount[plane].keys())
    yRaw = list(rawBitPlaneComplexityCount[plane].values())
    yStego = list(stegoBitPlaneComplexityCount[plane].values())

    plt.plot(xVals, yStego, label=f"Stego Bit Plane {7-plane}", color=colours[7-plane], linewidth=2)
    #plt.plot(xVals, yRaw, label=f"Raw Bit Plane {7-plane}", color=colours[7-plane], linewidth=2)

plt.title(f"Stego Complexity Distribution - Flapjack - Complexity Cutoff = {complexityCutoff}")
plt.xlabel("Complexity Value")
ax = plt.gca()
ax.xaxis.set_major_locator(MaxNLocator(nbins=20))
ax.yaxis.set_major_locator(MaxNLocator(nbins=20))
plt.ylabel("No. of Blocks")
plt.legend()
plt.grid()
plt.xlim(0, 1)
plt.show()