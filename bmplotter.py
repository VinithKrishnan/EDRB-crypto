import matplotlib.pyplot as plt

bfile = open("benchmarks.txt","r")
x_axis = []
y_axis = []
for f in bfile.readlines():
    t = f.split()
    x_axis.append(t[0])
    y_axis.append(t[1])
plt.plot(x_axis,y_axis)
plt.xlabel('Milliseconds')
plt.ylabel('Num. of nodes')
plt.show()
bfile.close()

