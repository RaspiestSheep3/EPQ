from PIL import Image
from pathlib import Path
from math import sqrt

scriptFolder = Path(__file__).parent 
stegoPath = scriptFolder / 'TestImageStego.png'

# Setup variables
width = 256
height = 256

chunkSize = 64

groupSize = 4
mask = [+1, 0, +1, 0]

def DiscriminantFunction(group):
    total = 0
    for i in range(len(group) - 1):
        total += abs(group[i + 1] - group[i])
    return total

def Flip(pixel, flip):
    if(flip == 1):
        if(pixel % 2 == 0):
            return pixel - 1
        else:
            return pixel + 1
    elif(flip == -1):
        if((pixel + 1) % 2 == 0):
            return pixel - 2
        else:
            return pixel
    else:
        return pixel

def CheckGroupType(group, negativeMult):
    discrimDefaultGroup = DiscriminantFunction(group)
    #Applying the mask
    newGroup = []
    for i in range(groupSize):
        newGroup.append(Flip(group[i], mask[i] * negativeMult))
    
    discrimNewGroup = DiscriminantFunction(newGroup)
    if(discrimNewGroup > discrimDefaultGroup):
        return "R"
    elif(discrimNewGroup < discrimDefaultGroup):
        return "S"
    else:
        return "U"

regularGroups = []
singularGroups = []
regularNegativeGroups = []
singularNegativeGroups = []

stego = Image.open(stegoPath)
stego = stego.convert("L")

totalPValue = 0
counter = 0

for l in range(width // chunkSize):
    for m in range(height // chunkSize):
        chunk = stego.crop((chunkSize * l, chunkSize * m, chunkSize * (l + 1), chunkSize * (m+1)))

        for j in range(chunkSize):
            for i in range(0, chunkSize, groupSize):
                group = [chunk.getpixel((i + k, j)) for k in range(groupSize)]
                groupTypeOut = CheckGroupType(group, 1)
                if(groupTypeOut == "R"):
                    regularGroups.append(group)
                elif(groupTypeOut == "S"):
                    singularGroups.append(group)
                
                groupTypeOutNeg = CheckGroupType(group, -1)
                if(groupTypeOutNeg == "R"):
                    regularNegativeGroups.append(group)
                elif(groupTypeOutNeg == "S"):
                    singularNegativeGroups.append(group)

        totalGroups = chunkSize * (chunkSize // groupSize)
        Rm = len(regularGroups)/totalGroups
        Sm = len(singularGroups)/totalGroups
        Rnm = len(regularNegativeGroups)/totalGroups
        Snm = len(singularNegativeGroups)/totalGroups
        Rm50 = 8192 #Mathematically calculated
        Sm50 = 8192
        #Display
        print("P/2 results : \n--------")
        print(f"Regular Groups              : {len(regularGroups)}={len(regularGroups) * 100/totalGroups}%")
        print(f"Singular Groups             : {len(singularGroups)}={len(singularGroups) * 100/totalGroups}%")
        print(f"Regular Negative Groups     : {len(regularNegativeGroups)}={len(regularNegativeGroups) * 100/totalGroups}%")
        print(f"Singular Negative Groups    : {len(singularNegativeGroups)}={len(singularNegativeGroups) * 100/totalGroups}%")

        #Finding the other sides
        regularGroupsFlipped = []
        singularGroupsFlipped = []
        regularNegativeGroupsFlipped = []
        singularNegativeGroupsFlipped = []

        for i in range(chunkSize // groupSize):
            for j in range(chunkSize):
                group = [Flip(chunk.getpixel((k, j)), 1) for k in range(i, i + groupSize)]
                groupTypeOut = CheckGroupType(group, 1)
                if(groupTypeOut == "R"):
                    regularGroupsFlipped.append(group)
                elif(groupTypeOut == "S"):
                    singularGroupsFlipped.append(group)
                
                groupTypeOutNeg = CheckGroupType(group, -1)
                if(groupTypeOutNeg == "R"):
                    regularNegativeGroupsFlipped.append(group)
                elif(groupTypeOutNeg == "S"):
                    singularNegativeGroupsFlipped.append(group)
                
        Rmf = len(regularGroupsFlipped)/totalGroups
        Smf = len(singularGroupsFlipped)/totalGroups
        Rnmf = len(regularNegativeGroupsFlipped)/totalGroups
        Snmf = len(singularNegativeGroupsFlipped)/totalGroups      
            
        #Display
        print("1- P/2 results : \n--------")
        print(f"Regular Groups              : {len(regularGroupsFlipped)}={len(regularGroupsFlipped) * 100/totalGroups}%")
        print(f"Singular Groups             : {len(singularGroupsFlipped)}={len(singularGroupsFlipped) * 100/totalGroups}%")
        print(f"Regular Negative Groups     : {len(regularNegativeGroupsFlipped)}={len(regularNegativeGroupsFlipped) * 100/totalGroups}%")
        print(f"Singular Negative Groups    : {len(singularNegativeGroupsFlipped)}={len(singularNegativeGroupsFlipped) * 100/totalGroups}%")

        d0 = Rm - Sm
        d1 = Rmf - Smf
        dn0 = Rnm - Snm
        dn1 = Rnmf - Snmf

        a = 2 * (d1 + d0)
        b = dn0 - dn1 - d1 - 3*d0
        c = d0 - dn0

        disc = b**2 - 4*a*c
        x1 = (-b + sqrt(disc)) / (2*a)
        x2 = (-b - sqrt(disc)) / (2*a)

        print(f"Roots : {x1}, {x2}")

        #x = x1 if abs(x1) < abs(x2) else abs(x2)
        #messageLengthPercentage = 2 * x
        #pValue = messageLengthPercentage

        messageLengthPercentages = (abs(x1/(x1-1/2)), abs(x2/(x2-1/2)))
        pValue = messageLengthPercentages[0] if messageLengthPercentages[0] < messageLengthPercentages[1] else messageLengthPercentages[1]
        
        totalPValue += pValue
        counter += 1

print(totalPValue / counter * 50)