Profil: Nivelul 1,2 - Domain Controller, Member Server

Autor: BSD Management

Acest script execută teste pe sistem pentru a verifica conformitatea cu CIS Microsoft Windows Server 2019 Benchmarks.
Acest script nu aduce modificări fișierelor de sistem. 

> Important: 	Scriptul se execută în mediul "PowerShell"
				Scriptul este necesar de executat sub un utilizator cu drepturi de administrator.

> Pentru a executa scriptul și obține probele este necesar să se urmeze următoarele etape:
	1. Se rulează consola "PowerShell" cu drepturi de administrator.
		- Apăsați tasta Win + R. O fereastră mică va apărea.
		- Tastați powershell și apăsați Ctrl + Shift + Enter.
		- Alte metode: https://adamtheautomator.com/powershell-run-as-administrator/
		
	2. În fereastra PowerShell deschisă, schimbăm path-ul către folderul în care este copiat scriptul, exemplu:
		- Set-Location C:\Users\username\Downloads
			or
		- cd C:\Users\username\Downloads
				
	3. Executam scriptul conform nivelului necesar și rolul serverului ce urmează a fi verificat (vezi mai jos Exemple de utilizare):
		.\scriptname.ps1 -L "1,2" -R DC
		
	4. Asteptam finisarea execuției pină se va afișa mesajul "DONE!".
	
	5. După finisarea execuției, în folderul părinte al scriptului va fi creată automat un fișier cu denumirea "Audit_Evidence_WinSer.*", necesară de copiat și de expediat către BSD. 
	

> Semnificația argumentelor:

	-L (Level) - argument utilizat pentru a se indica nivelul, contoalelor, dorit pentru verificare. 
		Obțiuni posibele:
			- 1 - testarea controalelor CIS de nivelul 1;
			- 2 - testarea controalelor CIS de nivelul 2;
			- "1,2" - testarea controalelor CIS de nivelul 1 și 2;
	-R (Role) - argument utilizat pentru a se indica rolul dserverului ce urmează a fi testat.
		Obțiuni posibile:
			- DC - Serverul ce urmează a fi testat deține rolul de Domen Controler
			- MS - Serverul ce urmează a fi testat deține rolul de Server Membru.
		
> Exemple de utilizare:
	- Pentru verificarea cofigurațiilor de "Nivelul 1", a unui server cu rolul de "Domen Controler", se utilizează comanda:
	.\scriptname.ps1 -L 1 -R DC
	
	- Pentru verificarea cofigurațiilor de "Nivelul 1", a unui server cu rolul de "Server Membru", se utilizează comanda:
	.\scriptname.ps1 -L 1 -R MS
	
	- Pentru verificarea cofigurațiilor de "Nivelul 2", a unui server cu rolul de "Domen Controler", se utilizează comanda:
	.\scriptname.ps1 -L 2 -R DC
	
	- Pentru verificarea cofigurațiilor de "Nivelul 1", a unui server cu rolul de "Server Membru", se utilizează comanda:
	.\scriptname.ps1 -L 2 -R MS
	
	- Pentru verificarea cofigurațiilor de "Nivelul 1 și 2", a unui server cu rolul de "Domen Controler", se utilizează comanda:
	.\scriptname.ps1 -L "1,2" -R DC
	
	- Pentru verificarea cofigurațiilor de "Nivelul 1 și 2", a unui server cu rolul de "Server Membru", se utilizează comanda:
	.\scriptname.ps1 -L "1,2" -R MS
	
	