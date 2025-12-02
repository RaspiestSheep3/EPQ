from PIL import Image
from pathlib import Path
from scipy.stats import chi2
import matplotlib.pyplot as plt

print("Running")

scriptFolder = Path(__file__).parent  
getPath = scriptFolder / 'TestImageStego.png'
getRawPath = scriptFolder / 'TestImage.png'

# Image dimensions
width = 256
height = 256

chunkSize = 32

img = Image.open(getPath)
imgRaw = Image.open(getRawPath)


print("Sorting")

widthOffset = 0
heightOffset = 0
chunkCounter = 0

xAxis = []
yAxis = []
yAxisRaw = []

#Getting amount of times each value pops up
for xBig in range(int(width / chunkSize)):
    for yBig in range(int(height / chunkSize)):
        
        valueDict = {}
        
        for x in range(widthOffset, chunkSize + widthOffset):
            for y in range(heightOffset, chunkSize + heightOffset):
                try:
                    L = img.getpixel((x,y))
                except:
                    print(x,y)
                    raise ValueError
                if not(L in valueDict):
                    valueDict[L] = 1
                else:
                    valueDict[L] = valueDict[L] + 1

        for i in range(255):
            if(i not in valueDict):
                valueDict[i] = 0

        #Sorting dict
        valueDict = dict(sorted(valueDict.items()))

        #print("Running Chi Square Attack")

        #Chi Square Attack
        total = 0
        for k in range(127):
            expectedCount = (valueDict[2*k] + valueDict[2*k + 1]) / 2
            if(expectedCount == 0):
                continue
            total += (((valueDict[2*k] - expectedCount) ** 2) / expectedCount) + (((valueDict[2*k + 1] - expectedCount) ** 2) / expectedCount)

        #print(total)

        df = 127
        p_value = chi2.sf(total, df)   # survival function = 1 - cdf
        print("chi2 =", total, " df =", df, " p =", p_value)
        
        xAxis.append(chunkCounter)
        yAxis.append(p_value)
        
        heightOffset = chunkSize * yBig
        chunkCounter += 1
    widthOffset = chunkSize * xBig

widthOffset = 0
heightOffset = 0
chunkCounter = 0

#Getting amount of times each value pops up for raw
for xBig in range(int(width / chunkSize)):
    for yBig in range(int(height / chunkSize)):
        
        valueDict = {}
        
        for x in range(widthOffset, chunkSize + widthOffset):
            for y in range(heightOffset, chunkSize + heightOffset):
                try:
                    L = imgRaw.getpixel((x,y))
                except:
                    print(x,y)
                    raise ValueError
                if not(L in valueDict):
                    valueDict[L] = 1
                else:
                    valueDict[L] = valueDict[L] + 1

        for i in range(255):
            if(i not in valueDict):
                valueDict[i] = 0

        #Sorting dict
        valueDict = dict(sorted(valueDict.items()))

        #print("Running Chi Square Attack")

        #Chi Square Attack
        total = 0
        for k in range(127):
            expectedCount = (valueDict[2*k] + valueDict[2*k + 1]) / 2
            if(expectedCount == 0):
                continue
            total += (((valueDict[2*k] - expectedCount) ** 2) / expectedCount) + (((valueDict[2*k + 1] - expectedCount) ** 2) / expectedCount)

        #print(total)

        df = 127
        p_value = chi2.sf(total, df)   # survival function = 1 - cdf
        print("chi2 =", total, " df =", df, " p =", p_value)
        
        yAxisRaw.append(p_value)
        
        heightOffset = chunkSize * yBig
        chunkCounter += 1
    widthOffset = chunkSize * xBig

print(xAxis)
print(yAxis)

#Saving DF data
with open(r"Steganography\EPQ\Steganalysis\ChiSquareRaw.csv", "w") as fileHandle:
    for i in range(len(xAxis)):
        fileHandle.write(str(xAxis[i]) + "," + str(yAxisRaw[i]) + "\n")

with open(r"Steganography\EPQ\Steganalysis\ChiSquareStego.csv", "w") as fileHandle:
    for i in range(len(xAxis)):
        fileHandle.write(str(xAxis[i]) + "," + str(yAxis[i]) + "\n")


plt.plot(xAxis,yAxisRaw, label="Raw", color="gray", linewidth=5)
plt.plot(xAxis,yAxis, label="Stego", color="red", linewidth=1)

plt.xlabel("Chunk Coordinate")
plt.ylabel("P value")

plt.legend()

plt.show()
