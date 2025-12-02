import matplotlib.pyplot as plt
import math

#Test variables
a = -2
b = 5
p = 97

#Runtime variables
points = []
xAxis = []

for x in range(p):
    RHS = (x ** 3 + a*x + b) % p
    #Finding valid y 
    for y in range(p):
        if ((y**2) % p) == RHS:
            if(y == 0):
                xAxis.append(x)
                points.append(y)
            else:
                xAxis.append(x)
                xAxis.append(x)
                points.append(y)
                points.append((-y) % p)

#Plotting points
plt.scatter(xAxis, points, label="Raw", color="red")
plt.hlines(y=[p/2], xmin=xAxis[0], xmax=xAxis[(len(xAxis) - 1)], colors=["blue"])
#plt.legend()
plt.show()
