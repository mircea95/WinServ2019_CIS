#!python3
'''
Scriptul acesta ii jopa, in sens ca lucreaza aiurea, si nu-i reutilizabil, este necesar de prelucrat.
El extrage cimpurile dorite din txt
Rezultatul necesita si un pic de prelucrare manuala
'''
import os, re

os.chdir('C:\\Users\\mirce\\Music\\CODE\\WINDOWS') # asta-i obtional, uneori VSCODE ruleaza din alta parte 
cisFile = open("CIS.txt",  encoding="utf8") # fisierul necesar de prelucrat
resfile = open('resultALL.txt', "w") # Fisierul in care se va salva rezultatul

## Creeam o lista cu toate rindurile din fisier
lines=[]
for line in cisFile:
    lines.append(line)
for j in range(10):
    lines.append(" ")

# regex 
regex = re.compile(r'^\d*\.\d*\.') # cifra.cifra.

# Variabile de afisare
n = 0
nt = 0
p = 'Profile Applicability:\n'

## Mergem prin fiecare element al listei
for i in range(len(lines)):
    row = ""
    if lines[i] == p: #Pentru orientarea, numarul de controale extrase trebuie sa fie egal cu valoarea aceasta
        n += 1
    # iful acesta verifica daca rindul incepe cu regexu setat si daca in urmatoarele 6 rinduri este prezent rindul cu valoarea p. Daca da inseamna ca este un control.
    elif regex.search(lines[i]) != None and (lines[i+1] == p or lines[i+2] == p or lines[i+3] == p or lines[i+4] == p or lines[i+5] == p or lines[i+5] == p or lines[i+6] == p):
        nt += 1 # Pentru a vedea cite controale sa prelucrat
        for j in range(6): # Mergem pe urmatoarele 6 rinduri de la identificarea controlului
            if regex.search(lines[i+j+1]) != None: 
                break # Daca unul dintre cele 6 rinduri la fel incepe cu regex atunci break
            elif lines[i+j] == 'Description:\n':
                break # Daca rindul este Description atunci break
            elif lines[i+j] == p:
                continue # Daca rindul este egala cu valoarea lui p atun sarim
            else: 
                if lines[i+j][0:5] == "Level":
                    row = row + " *** " + lines[i+j][0:-1] # Daca rindul incepe cu cuvintul Level, atunci il scrim cu delimitator ***
                else:
                    row = row + " " + lines[i+j][0:-1] # Daca rindul incepe cu caractere, continuarea la denumirea controlului, atunci se adauga ca continuare la variabila row, prin spatiu
        resfile.writelines(row + "\n")
resfile.close()   
print("Done")
print("Profile Applicability:" + str(n))
print("Controale:" + str(nt))
