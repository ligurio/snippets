#!/usr/local/bin/python

"""
https://askubuntu.com/questions/56225/is-there-an-gui-designer-for-python
https://www.tutorialspoint.com/python/python_gui_programming.htm
https://likegeeks.com/python-gui-examples-tkinter-tutorial/
https://www.geeksforgeeks.org/python-gui-tkinter/
https://docs.python.org/3/library/tkinter.html
"""

from tkinter import *
from tkinter.ttk import *
import json

class Config:
    def __init__(filename):
        self.filename = filename
        self.config = {}

    def write(self):
        with open(self.filename, "w") as f:
            json.dump(self.config, f, indent=4, sort_keys=True)

    def read(self):
        with open(self.filename, 'r') as f:
            data = f.read()
            self.config = json.loads(data)

def main():
    window = Tk()
    window.title("Hive Job Configuration Tool")

    winWidth = window.winfo_reqwidth()
    winHeight = window.winfo_reqheight()
    posRight = int(window.winfo_screenwidth() / 2 - winWidth / 2)
    posDown = int(window.winfo_screenheight() / 2 - winHeight / 2)
    window.geometry("+{}+{}".format(posRight, posDown))
    window.configure(width=500, height=300, bg='lightgray')

    lbl = Label(window, text="Hello")
    lbl.grid(column=0, row=0)
    #button = Button(window, text='Stop', width=25, command=window.destroy)
	#button.pack()
	# window.geometry('350x200')
    lbl = Label(window, text="Hello")
    lbl.grid(column=0, row=0)
    txt = Entry(window,width=10)
    txt.grid(column=1, row=0)
    def clicked():
        res = "Welcome to " + txt.get()
        lbl.configure(text= res)
    btn = Button(window, text="Click Me", command=clicked)
    btn.grid(column=2, row=0)
    lbl = Label(window, text="Hello", font=("Arial Bold", 50))

    combo = Combobox(window)
    combo['values']= (1, 2, 3, 4, 5, "Text")
    combo.current(1)
    combo.grid(column=0, row=0)
    window.mainloop()

main()
