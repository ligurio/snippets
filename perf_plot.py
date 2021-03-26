# https://matplotlib.org/3.1.0/tutorials/colors/colormap-manipulation.html
# https://s3.amazonaws.com/assets.datacamp.com/production/course_2493/slides/ch2_slides.pdf
# https://stackoverflow.com/questions/57493795/matplotlib-combine-gradient-colormap-with-listed-colormap
# https://github.com/etcd-io/etcd/pull/12692

import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib.colors import LinearSegmentedColormap

Z = np.random.rand(30, 30)*10-5
print(Z)

thresh = 0.1
nodes = [0, thresh, thresh, 1.0]
colors = ['red', 'grey', 'grey', 'green']
# cmap = mpl.colors.ListedColormap(['red', 'grey','green'])
# cmap = 'autumn'
cmap = LinearSegmentedColormap.from_list("", list(zip(nodes, colors)))
cmap.set_under("grey")

img = plt.imshow(Z, interpolation='nearest', cmap=cmap, alpha=0.85)

plt.colorbar(img, cmap=cmap, ticks=[-5,0,5])
# plt.title('performance', size=16)
plt.ylabel('speed', size=12)
plt.xlabel('connections', size=12)
plt.show()

# ======================================================

"""
import pandas as pd
import matplotlib.pyplot as plt

N = 3
df = pd.read_csv('perf.csv')
print("raw", df)
df['avg'] = df.iloc[:, 2: ].sum(axis=1)/5.0 # getting average
df = df.iloc[:, [0, 1, N]]
print("iloc", df)

plt.tripcolor(df.iloc[:, 0], df.iloc[:, 1], df.iloc[:, 2])
plt.title('Master Branch Txn-Put Performance')
plt.yscale('log', basey=2)
plt.ylabel('Value Size')
plt.xscale('log', basex=2)
plt.xlabel('Connections Amount')
plt.colorbar()
plt.show()
"""