#!python3

import os, re

os.chdir('C:\\Users\\mirce\\Music\\CODE\\WINDOWS') # asta-i obtional, uneori VSCODE ruleaza din alta parte, aici trebuie sa fie fisierul newline.txt
txtFile = open("newline.txt",  encoding="utf8")
resfile = open('result.txt', "w")

# punem toate rindurile din fisier intr-o lista
lines=[]
for line in txtFile:
    lines.append(line)
lines.append(" ") # mai adaugat un element ca sa poata verifica +2

### regex 
regex = re.compile(r'^\D') # orice rind care nu incepe cu cifre
#regexD = re.compile(r'^\d+') # rindurile care incep cu cifre

for i in range(len(lines)):

    if regex.search(lines[i]) == None and regex.search(lines[i+1]) == None:
        resfile.writelines(lines[i]) #scrim in fisier rindul care e complet

    elif regex.search(lines[i]) == None and regex.search(lines[i+1]) != None and regex.search(lines[i+2]) != None:
        resfile.writelines(lines[i][0:-1] + " " + lines[i+1][0:-1] + " " + lines[i+2]) # scrim in fisier rindul care se termina pe urmatorul(-1 e pentru a sterge \n)
        i += 2 # incrementam unu deoarece rindul nefinisat deja a fost procesat

    elif regex.search(lines[i]) == None and regex.search(lines[i+1]) != None and regex.search(lines[i+2]) == None:
        resfile.writelines(lines[i][0:-1] + " " + lines[i+1]) # scrim in fisier rindul care se termina pe urmatorul(-1 e pentru a sterge \n)
        i += 1 # incrementam unu deoarece rindul nefinisat deja a fost procesat

resfile.close()
print("Done")