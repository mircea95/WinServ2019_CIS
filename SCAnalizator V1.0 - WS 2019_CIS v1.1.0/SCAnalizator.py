#!python3

import os, re, openpyxl

# Deschidem excelul de lucru
wb = openpyxl.load_workbook(os.getcwd() + '\\bin\\CIS_2019(WorkFile).xlsx')
sheet = wb['WS2019']
if sheet:
    print("(+) Work Excel File is Ready!!!")
else:
    print("(-) Can't load excel file from /bin folder")
    quit()
# Loop over the files in the working directory.
# Cautam in folderul scriptului fisierul denumirea caruia se incepe cu Audit_Evidence(fisierul cu rezultatele obtinute in urma rularii scriptului)
for res_file in os.listdir('.'):
    if res_file[:14] == "Audit_Evidence":
        print("(+) " + res_file + " file was found!")
        break
    else:
        print("(-) Error: Can't find 'Audit_Evidence.*' file! Check again '" + os.getcwd() + "' location path and ensure with file exist here!")
        quit()

# Deschidem fisierul CIS MWS 2019
cisWS_file = open(os.getcwd() + "\\bin\\CIS_Microsoft_Windows_Server_2019_RTM_Release_1809_Benchmark_v1.1.0.txt",  encoding="utf8") # fisierul necesar de prelucrat
if cisWS_file:
    print("(+) CIS_Microsoft_Windows_Server_2019 file was loaded.")
else:
    print("(-) Can't load 'CIS_Microsoft_Windows_Server_2019' file.")
    quit()

# Deschidem fisierul cu rezultatele obtinute
aud_eviF = open(res_file,  encoding="utf8") # fisierul necesar de prelucrat

##===============================================================================##
## Adaugare informatie in liste 
## Regex 
regex = re.compile(r'^(\d+\.\d.*?)\s') # incepe cu cifra si punct
## Lista cu toate rindurile din fisier
aud_eviListAll=[]
## Lista cu numerele controalelor, utilizat pentru a compara in excel
aud_eviListCNr=[]
for line in aud_eviF:
    aud_eviListAll.append(line)
    if regex.search(line) != None:
        aud_eviListCNr.append(regex.search(line).group())
## Lista toate rindurile din fisierul
cisallLine=[]
for line in cisWS_file:
    cisallLine.append(line)

## Afisare date adaugate in lista 
print("\n(+) Result file contain " + str(len(aud_eviListAll)) + " rows")
print("(+) " + str(len(aud_eviListCNr)) + " controls was found in result file\n")

print("Working, please wait....\n")

delrows = 0 
pro = 'Profile Applicability:\n'   
rat = 'Rationale:\n' 
rem = 'Remediation:\n'        
for rowNum in range(2, sheet.max_row+1): # skip the first row
    contrName = str(sheet.cell(row=rowNum-delrows, column=3).value) + "\n"
    if contrName in aud_eviListAll:
        ## Adaugare in excel informatie despre statutul controlului
        locationC = aud_eviListAll.index(contrName)
        for i in range(20):
            if aud_eviListAll[locationC + i] == "Fail\n" or aud_eviListAll[locationC + i] == "Pass\n":
                sheet.cell(row=rowNum-delrows, column=4).value = aud_eviListAll[locationC + i]
                break
        ## Adaugare in excel informatie despre explicatie si tratarea controlului
        done = False
        for line in cisallLine:
            if done:
                break
            elif regex.search(line) != None and regex.search(line).group() == sheet.cell(row=rowNum-delrows, column=2).value:
                #if  regex.search(line).group() == '1.1.6 ':
                #    print(sheet.cell(row=rowNum-delrows, column=2).value)
                indexloc = cisallLine.index(line) 
                for i in range(10):
                    if i+1 == 10:
                        cisallLine[indexloc] = cisallLine[indexloc] + "fail" 
                    elif cisallLine[indexloc + i] == pro:
                        # daca suntem aici inseamna ca suntem, in fisierul CIS 2016, la locatia controlului care ne intereseaza
                        done = True
                        ratText = '\n'
                        remText = '\n'
                        for j in range(100):
                            if cisallLine[indexloc + i + j] == rat:
                                indfortext = 1
                                while cisallLine[indexloc + i + j + indfortext] != 'Audit:\n':
                                    ratText = ratText[0:-1] + " " + cisallLine[indexloc + i + j + indfortext]
                                    indfortext += 1                              
                                break
                        # aici punem valoare in excel 
                        sheet.cell(row=rowNum-delrows, column=5).value = ratText[1:]
                        for j in range(100):                             
                            if cisallLine[indexloc + i + j] == rem:
                                indfortext = 1
                                while cisallLine[indexloc + i + j + indfortext] != 'Impact:\n':
                                    remText = remText[0:-1] + " " + cisallLine[indexloc + i + j + indfortext] 
                                    indfortext += 1
                                break
                        # aici punem valoare in excel
                        sheet.cell(row=rowNum-delrows, column=6).value = remText[1:]
                        break                      
    else:
        sheet.delete_rows(rowNum - delrows)
        delrows += 1  

## salvam excelul cu rezultatele extrase
wb.save('result_analysis .xlsx')

##===============================================================================##
print("Checking for gaps...")

## Lista cu Nr controalelor din excel
aud_excelCNr=[]
for row in sheet.iter_rows(min_row=2, min_col=2, max_row=sheet.max_row, max_col=2):
    for cell in row:
        aud_excelCNr.append(cell.value)

notfoundC = 0
for index in range(len(aud_eviListCNr)):
    if aud_eviListCNr[index] not in aud_excelCNr:
        print("Need to add manual in excell: " + aud_eviListCNr[index])
        notfoundC += 1
print("\n(+) From " + str(len(aud_eviListCNr)) + ", " + str(len(aud_eviListCNr) - notfoundC) + " controls have been added in excel!\n")

