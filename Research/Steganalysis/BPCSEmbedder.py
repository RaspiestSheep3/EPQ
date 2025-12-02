from PIL import Image
from pathlib import Path
import random
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

scriptFolder = Path(__file__).parent 
getPath = scriptFolder / 'TestImage.png'
savePath = scriptFolder / 'TestImageStego.png'

#For this experiment we will be embedding the equivalent of a 128*128 image into a 256*256 image

#*Test controllers
complexityThreshold = 0.4
dataAmount = 16100
coverSize = (256,256)

def GrayToBinary(gray):
    binary = gray 
    while gray > 0: 
        gray >>= 1 
        binary ^= gray 
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

def ConjugateBlock(blockArray):
    #print("Conjugating")
    Wc = [[(i + j) % 2 for j in range(8)] for i in range(8)]
    outputArray = [[0 for _ in range(8)] for __ in range(8)]
    for i in range(8):
        for j in range(8):
            outputArray[i][j] = blockArray[i][j] ^ Wc[i][j]
    
    return outputArray


class Block():
    def __init__ (self,bitPlane, blockArray):
        self.bitPlane = bitPlane
        self.blockArray = blockArray
        self.complexity = FindComplexity(self.blockArray)

#Generating the cover image arrays
coverImageArrays = [[] for _ in range(8)]
img = Image.open(getPath)
for x in range(coverSize[0]):
    rows = [[] for _ in range(8)]
    #print(rows)
    for y in range(coverSize[1]):
        cell = img.getpixel((x,y))
        #Converting from PBC to CGC
        cellShift = cell >> 1
        cellCGC = cell ^ cellShift
        
        #print(cellCGC, end=" ")
        #print(cell, cellCGC, GrayToBinary(cellCGC))
        
        for i in range(8):
               rows[7-i].append(int(cellCGC & pow(2, i) != 0))
    #print("", end="\n")
        
    for j in range(8):
        coverImageArrays[j].append(rows[j])

print("-----")

blocksCover = []
#Generating the blocks for the cover
for i in range(8):
    bitPlane = coverImageArrays[i]
    planeBlocks = []
    for j in range(int(coverSize[0] / 8)):
        blockRow = []
        for k in range(int(coverSize[1] / 8)):
            #Setting this section to be a Block 
            blockArray = []
            for l in range(8):
                row = []
                for m in range(8):
                    row.append(bitPlane[j * 8 + l][k*8 + m])
                blockArray.append(row)
            
            block = Block(i, blockArray)
            blockRow.append(block)
        planeBlocks.append(blockRow)
    blocksCover.append(planeBlocks)

print(len(blocksCover), len(blocksCover[0]) * 8)
#print([[[block.blockArray[0][0] for block in blockRow] for blockRow in planeBlocks] for planeBlocks in blocksCover])
#print(blocksCover[0][0][0].bitPlane, blocksCover[0][0][0].blockArray)
print("-----")

#Graph generation 
minComplexity = 0
maxComplexity = 1
complexityStep = 0.05
complexityLoop = minComplexity
xAxis = []
yAxes = [[] for _ in range(8)]

while(complexityLoop - complexityStep <= maxComplexity):
    for bitPlane in blocksCover:
        total = 0
        for row in bitPlane:
            for block in row:
                if(block.complexity) > complexityLoop:
                    total += 1
        yAxes[blocksCover.index(bitPlane)].append(total)
    xAxis.append(complexityLoop)
    complexityLoop += complexityStep
    print(f"{block.complexity}, {complexityLoop}")

colours = ["red", "blue", "green", "orange", "purple", "pink", "gray", "black"]

for yAxis in yAxes:
    #print(yAxis)
    plt.plot(xAxis,yAxis, label=(f"Bit Plane {7-yAxes.index(yAxis)}"), color=colours[7-yAxes.index(yAxis)], linewidth=2)

plt.xlabel("Complexity Value")
ax = plt.gca()
ax.xaxis.set_major_locator(MaxNLocator(nbins=20))  
ax.yaxis.set_major_locator(MaxNLocator(nbins=20))  
plt.ylabel("No. of blocks")
plt.legend()
plt.grid()
plt.xlim(minComplexity, maxComplexity)
plt.title(f"No. of Blocks With A Complexity > Given Complexity Value - {input("What is the image name : ")}")
plt.show()

#Converting data to CGC
with open(r"EPQ\Steganalysis\DataToEmbed.txt", "r") as fileHandle:
    dataToEmbed = fileHandle.read(dataAmount)

dataToEmbedCGC = []
for char in dataToEmbed:
    bytePBC = ord(char)  
    byteCGC = bytePBC ^ (bytePBC >> 1) 
    dataToEmbedCGC.append(byteCGC)

#Padding the data with NULs
print(len(dataToEmbedCGC) / 64)
if(len(dataToEmbedCGC) % 64 != 0):
    dataToEmbedCGC += [b"\0" for _ in range(64 - (len(dataToEmbedCGC) % 64))]
    print(len(dataToEmbedCGC) / 64)

print("-----")

#Generating the blocks for secrets
blocksSecret = [[] for _ in range(8)]
for x in range(int(len(dataToEmbedCGC) / 64)):
    dataToEmbedInBlock = dataToEmbedCGC[x*64 : (x+1)*64]
    dataToEmbedInBlockSplit = []
    for blockData in dataToEmbedInBlock:
        bitPlaned = []
        for i in range(8):
            if blockData == b"\0":
                blockInt = 0
            else:
                blockInt = int(blockData)
            
            bitPlaned.append(int(blockInt & pow(2, i) != 0))
        dataToEmbedInBlockSplit.append(bitPlaned)
    
    dataToEmbedInBlockSplitOrganised = [dataToEmbedInBlockSplit[i:i + 8] for i in range(0,64,8)]
    #print(dataToEmbedInBlockSplitOrganised)
    
    for i in range(8):
        #Generating the block array
        blockArray = []
        for j in range(8):
            row = dataToEmbedInBlockSplitOrganised[j]
            #print(row)
            pixelPoints = [row[k][i] for k in range(8)]
            blockArray.append(pixelPoints)
        
        block = Block(7-i, blockArray)
        #print(f"Block : {block}, bitPlane : {block.bitPlane}, i : {7-i}")
        blocksSecret[7-i].append(block)

#print(blocksSecret)
print("---------")
#print([[block.bitPlane for block in blockRow] for blockRow in blocksSecret])
#print([[block.complexity for block in blockRow] for blockRow in blocksSecret])
print("---------")
for blockRow in blocksSecret:
    for block in blockRow:
        #print(block)
        if(block.complexity <= complexityThreshold  and block.complexity != 0):
            blockConjugated = Block(block.bitPlane, ConjugateBlock(block.blockArray))   
            blockRow[blockRow.index(block)] = blockConjugated

#print(f"Complexities : {[[block.complexity for block in blockRow] for blockRow in blocksSecret]}")
#print(f"Check : {blocksCover[7][0][0].blockArray}")
print("------")

#Finding noisy cover blocks
noisyBlocksCover = [] 
for blockPlane in blocksCover:
    for blockRow in blockPlane:
        for block in blockRow:
            #print(block.complexity)
            if(block.complexity > complexityThreshold):
                noisyBlocksCover.append(block)

print(len(noisyBlocksCover))
print("------")

#Randomly picking which blocks to use and replacing them
#* In a real application this would be seeded, but this is a test so I am not seeding it
targetedBlocks = []
secretBlocksFlattened = [block for row in blocksSecret for block in row]
print(f"Len BlocksSecretFlattened : {len(secretBlocksFlattened)}")
for secretBlock in secretBlocksFlattened:
    targetedBlock = random.choice(noisyBlocksCover)
    targetedBlocks.append(targetedBlock)
    noisyBlocksCover.remove(targetedBlock)

for blockPlane in blocksCover:
    for blockRow in blockPlane:
        for block in blockRow:
            if(block in targetedBlocks):
                blockRow[blockRow.index(block)] = secretBlocksFlattened[targetedBlocks.index(block)]

print(f"Targeted Blocks : {len(targetedBlocks)}")
print("-------")

#Restiching the image 
# Initialize empty image array
imageRestich = [[0 for _ in range(coverSize[1])] for __ in range(coverSize[0])]

# Loop over each bit plane
"""for bitPlaneCounter in range(7, -1, -1):
    planeBlocks = blocksCover[bitPlaneCounter]
    print(planeBlocks[0][0].blockArray, planeBlocks[0][0].complexity)
    print("!---------")
    blocksPerRow = len(planeBlocks)
    blocksPerCol = len(planeBlocks[0])

    for blockRowIndex in range(blocksPerRow):
        for blockColIndex in range(blocksPerCol):
            block = planeBlocks[blockRowIndex][blockColIndex].blockArray
            print(f"Plane : {bitPlaneCounter}, Block Array: {block}")
            # Loop over pixels inside the block
            for i in range(8):
                for j in range(8):
                    x = blockRowIndex * 8 + i
                    y = blockColIndex * 8 + j
                    if x < coverSize[0] and y < coverSize[1]:
                        imageRestich[x][y] += (2 ** bitPlaneCounter) * block[i][j]
                        print(f"plane : {bitPlaneCounter} x, y : {x}, {y}, ij : {block[i][j]},  xy : {imageRestich[x][y]}")"""

for bitPlaneCounter in range(8):
    bitPlane = blocksCover[bitPlaneCounter]
    for i in range(len(bitPlane)):
        for j in range(len(bitPlane[i])):
            blockArray = bitPlane[i][j].blockArray
            
            for k in range(8):
                for l in range(8):
                    imageRestich[i*8 + k][j * 8 + l] += 2**(7 - bitPlaneCounter) * blockArray[k][l]

# Convert to PIL Image and save
outputImg = Image.new("L", coverSize)
for x in range(coverSize[0]):
    for y in range(coverSize[1]):
        outputImg.putpixel((x, y), GrayToBinary(imageRestich[x][y]))
        #print(GrayToBinary(imageRestich[x][y]))

outputImg.save(savePath)
print(f"Saved stego image to {savePath}")

"""for i in range(8):
    print(f"Plane {7-i}:")
    for row in coverImageArrays[i]:
        print(row)
    print("--------") """