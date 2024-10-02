# Configuración de la máquina

## A) Configure su máquina virtual de laboratorio con los datos proporcionados por el profesor.

### Analice los ficheros básicos de configuración

- `/etc/network/interfaces` -> Se emplea para configurar las interfaces de red (IP estáticas, DHCP...)
	
- `/etc/hosts` -> Asocia nombres de host a direcciones IP en la maquina local (resolv nombres antes de consultar servidores DNS)
	
- `/etc/resolv.conf` -> para configurar los servidorers DNS que debe usar el sistema
	
- `/etc/nsswitch.conf` -> Controla la resolución de nombres del sistema. Define la secuencia de fuentes que se utilizarán para buscar información (ej, usuarios y grupos, en diferentes bases de datos, como archivos locales)

- `/etc/apt/sources.list` -> se especifican los repositorios software desde los que se pueden instalar paquetes (esencial para gestion de paquetes y actualizaciones del sistema)

- `/etc/hostname` -> nombre de la máquina

- `/etc/hosts.allow` & `/etc/hosts.deny` -> para configurar reglas de acceso al sistema (a través de TCP wrappers). Definen que hosts o servicios están permitidos o denegados

- `/etc/ssh/sshd_config` -> configuracion del servidor ssh (incluye opciones seguridad y autenticación)

- `/etc/fstab` -> define como se deben montar los sistemas de archivos. (info sobre particiones, dispositivos y puntos de montaje)

- `/etc/timezone` & `/etc/localtime` -> zona horaria e info de hora local (usar zdump para ver contenido de /etc/localtime)

## B) Actualice su máquina a la última versión estable disponible.

### Update

- ⚠: Revisar apartado R) primero para facilitar

### ¿Qué distro y versión tiene la máquina inicialmente entregada?.

- Podemos ver la versión utilizando los comandos `cat /etc/os-release` o `cat /etc/debian_version`

- Empezamos con un debian **10.5** y lo updateamos hasta un debian **12.7**

## C) Identifique la secuencia completa de arranque de una máquina basada en la distribución de referencia (desde la pulsación del botón de arranque hasta la pantalla de login)

### Secuencia

Secuencia de arranque:

- Inicio del firmware del sistema (BIOS/UEFI). Se realizan comprobaciones de hardware y se busca el bootloader en el dispositivo de inicio establecido

- El bootloader (en este caso el grub de arranque) se carga desde dicho dispositivo. Su tarea es cargar el kernel del SO principalmente

- Una vez cargado, el kernel toma el control del hardware e inicializa el sistema (hardware, drivers, creación de procesos esenciales...)

- Systemd (init) (o Systemd(1) (PID=1)) -> systemd es el sistema de inicialización empleado en debian. Gestiona servicios y procesos del sistema. Carga el objetivo (target) predeterminado configurado para el sistema durante el proceso de instalación

- El proceso de arranque, termina su ejecución con systemd, que luego prepara el sistema para que el usuario inicie sesión (pantalla de login es una parte separada del proceso)

### ¿Qué target por defecto tiene su máquina?

- Para ver el target por defecto `systemctl get-default` -> `graphical.target` (en este caso)

- Para cambiar el target: `sudo systemctl set-default multi-user.target` (lo cambiamos a **multiuser**)

### ¿Qué targets tiene su sistema y en qué estado se encuentran?.

- Para ver el listado de targets: `systemctl list-units --type=target (-all)`

## ¿Y los services? Obtenga la relación de servicios de su sistema y su estado.

- Para ver el listado de servicios: `systemctl list-units --type=service (-all)`

## ¿Qué otro tipo de unidades existen?

Otros tipos de unidades:

- Timers -> Permiten programar tareas para que se ejecuten en momentos específicos
- Sockets -> Gestionan sockets y conexiones de red
- Paths -> supervisan combios en rutas de sistema de archivos (pueden activar otras unidades en respuesta a los cambios)
- Devices -> representan dispositivos gestionados por systemd
- Mounts -> gestionan puntos de montaje de sistema de archivos
    - 'automount' -> se utiliza para definir puntos de montaje automático para sistemas de archivos. Se emplea junto con unidades de tipo
    - 'mount' para montar sistemas de archivos automáticamente al acceder a ellos
    - 'mount' -> define puntos de montaje de sistemas de archivos. Indica a systemd cómo montar o desmontar sistemas de archivos (particiones de disco...)
        - 'slice' -> se utilizan para agrupar procesos en "rebanadas" (por el nombre) con recursos limitados. Ayudan a gestionar prioridad de procesos y recursos en un sistema
        - Se pueden explorar las unidades en los directorios /etc/systemd/system y /lib/systemd/system (archivos con exensiones .service, .target, .timer...). (Podemos servirnos del comando ls -1 /lib/systemd/system | awk -F. '{print $NF}' | sort -u para obtener las distintas extensiones de dichos directorios)

	
### Configure el sudo de su máquina

- Para añadir tu usuario a sudo: `sudo usermod -aG sudo nombre_de_usuario` 

## D) Determine los tiempos aproximados de botado de su kernel y del userspace.

### Tiempo de booteado

- Para ver el tiempo que tarda en bootear la máquina: `systemd-analyze`

###  Obtenga la relación de los tiempos de ejecución de los services de su sistema.

- Para ver la relación tiempo-servicio:  `systemd-analyze blame`

## E) Investigue si alguno de los servicios del sistema falla

### Fallos

- Para ver los fallos de los servicios: `systemctl --failed` o `systemctl list-units --type=service --state=failed`

### Pruebe algunas de las opciones del sistema de registro journald.

- `journalctl -b -p 4` (muestra el ultimo registro de journal(-b) de nivel warning para arriba (-p 4))

### Obtenga toda la información journald referente al proceso de botado de la máquina.

- Para obtener esta ibfo ejecutamo: `journalctl -b`

### ¿Qué hace el systemd-timesyncd?

- El servicio `systemd-timesyncd` es un cliente SNTP que se utiliza para sincronizar la hora del sistema con los servidores de hora (Responsable de mantener la hora del sistema actualizada)

## F) Identifique y cambie los principales parámetros de su segundo interface de red (ens34)

### Configuración ens34
    # This file describes the network interfaces available on your system
    # and how to activate them. For more information, see interfaces(5).
    #source /etc/network/interfaces.d/*
    # The loopback network interface
    auto lo ens33 ens34 
    iface lo inet loopback

    iface ens33 inet static
            address 10.11.X.X/23
            gateway 10.11.48.1
            dns-nameservers 10.8.12.47 10.8.12.49 10.8.12.50
    iface ens34 inet static
            address 10.11.X.X/23

### Configure un segundo interface lógico. Al terminar, déjelo como estaba.

    auto ens34:1
	iface ens34:1 inet static -> tmb valdría poner ens34:0
	address 10.11.52.X
	netmask 255.255.254.0
	broadcast 10.11.52.255
	network 10.11.52.0

## G) ¿Qué rutas (routing) están definidas en su sistema?

### Ver rutas

- Para ver las rutas: `ip route` o `netstat -r`

###  Incluya una nueva ruta estática a una determinada red.

- Añadir ruta temporalmente(durante la sesión): `sudo ip route add 10.11.X.X via 10.11.48.1 dev ens33`

- Añadir ruta permanente:

        (post-)up ip route add 10.11.X.X via 10.11.48.1 (dentro de la interfaz ens 33 bien identado)

## H) En el apartado d) se ha familiarizado con los services que corren en su sistema. ¿Son necesarios todos ellos?.

### Si identifica servicios no necesarios, proceda adecuadamente. Una limpieza no le vendrá mal a su equipo, tanto desde el punto de vista de la seguridad, como del rendimiento.

- ⚠: Revisar apartado R) primero para facilitar

- Servicios deshabilitados (especificar porqué)
    - **journal.flush.service**
    - **apparmore** 
    - **avahi daemon** 
    - **e2scrub**  

# I) Diseñe y configure un pequeño “script” y defina la correspondiente unidad de tipo service para que se ejecute en el proceso de botado de su máquina.

## Diseño de script

    #!/bin/bash
    # Este es un ejemplo de script que crea un archivo de log al arrancar el sistema.
    echo "El sistema arrancó correctamente a las $(date)" >> /tmp/mi_log.txt

# Pasos para crearlo

    1.Crea un archivo de script en el directorio /usr/local/bin/ ""sudo nano /usr/local/bin/mi_script.sh""
    2.Dale permisos con: "sudo chmod +x /usr/local/bin/mi_script.sh"
    3.Ahora, crearemos el archivo de unidad de systemd para que este script se ejecute durante el arranque del sistema.
        3.1.Usaremos: "sudo nano /etc/systemd/system/mi_servicio.service"
        3.2.Configuración: 

            [Unit]
            Description=Servicio que ejecuta un script personalizado en el arranque
            After=network.target

            [Service]
            ExecStart=/usr/local/bin/mi_script.sh
            Type=oneshot
            RemainAfterExit=yes

            [Install]
            WantedBy=multi-user.target
        3.3.PorQué?
            - After=network.target: Esto asegura que el servicio se ejecute después de que la red esté activa.
            - ExecStart=/usr/local/bin/mi_script.sh: Especifica el script que se ejecutará.
            - Type=oneshot: El tipo oneshot significa que el script se ejecuta una vez y luego el servicio termina.
            - RemainAfterExit=yes: Esto mantiene el servicio en estado activo incluso después de que el script haya terminado.
            - Si deseas que un servicio esté disponible en múltiples targets, deberás hacer que el servicio dependa explícitamente de esos targets.
            - Uso de WantedBy: La opción WantedBy= en la sección [Install] de tu archivo de servicio indica qué target activará tu servicio. Si deseas que tu servicio se inicie en otros targets, como graphical.target, también deberás añadir esa línea.
    4.Habilitar el servicio: "sudo systemctl enable mi_servicio.service"
    5.Iniciarlo y verificar: "sudo systemctl start mi_servicio.service" y "sudo systemctl status mi_servicio.service"

## Explicación de este servicio

    Al crear un servicio en systemd, es importante elegir el target correcto para asegurarte de que el servicio se inicie en el momento adecuado del proceso de arranque y en el contexto correcto.
    Asegúrate de que el servicio no dependa de otros servicios o recursos que aún no estén disponibles en el target que has elegido.
    Si tu script no depende de una interfaz gráfica y está diseñado para ejecutarse en un entorno de servidor o en la consola, multi-user.target es un buen lugar para él.
    Asegúrate de que cualquier servicio del que tu script dependa esté activo antes de que tu script se ejecute.

    Qué hace? Cada vez que este script se ejecuta (en este caso, al arrancar el sistema si está configurado para ello), se añade una línea al archivo /tmp/mi_log.txt con un mensaje

    Dependencias anteriores y futuras:

    el script necesita que la red esté disponible antes de ejecutarse (After=network.target) esto garantiza que el servicio se inicie después del servicio o target que especifiques.

    systemctl list-dependencies mi_servicio.service
    mi_servicio.service
    ● ├─system.slice
    ● └─sysinit.target

    systemctl list-dependencies --reverse mi_servicio.service
    mi_servicio.service
    ● └─multi-user.target
    ○   └─graphical.target

    Dónde se instala?
    El servicio está instalado en el target multi-user.target. 
    La opción WantedBy= en la sección [Install] de tu archivo de servicio indica qué target activará tu servicio
    [Install]
    WantedBy=multi-user.target
    Por qué?
    Los servicios que se inician en este target suelen ser aquellos que no dependen de un entorno gráfico. Este nivel es común en servidores o sistemas que no requieren una interfaz gráfica.

# J) Identifique las conexiones de red abiertas a y desde su equipo.

##  Conexiones

    Para ver las conexiones: "netstat -tuln / ss -tuln"

        -t: muestra las conexiones TCP.
        -u: muestra las conexiones UDP.
        -l: muestra solo las conexiones que están escuchando.
        -n: muestra las direcciones y números de puerto en formato numérico.
        
    Se puede usar para listar las conexiones de red abiertas: "lsof -i"

    Para ver las interfaces de red y sus configuraciones: "ip a"

    Si estás interesado en las reglas de firewall y las conexiones permitidas/denegadas: "iptables -L -v -n"

    Las conexiones que están en LISTEN están esperando conexiones entrantes (abiertas a tu equipo).
    Las conexiones con el estado ESTABLISHED muestran que tu equipo está conectado a otro (abiertas desde tu equipo).


# K) Nuestro sistema es el encargado de gestionar la CPU, memoria, red, etc., como soporte a los datos y procesos.

## Monitorice en “tiempo real” la información relevante de los procesos del sistema y los recursos consumidos.

    - "top": es una herramienta de monitorización en tiempo real que muestra los procesos en ejecución y el uso de recursos del sistema.

    - "vmstat": proporciona información sobre procesos, memoria, paginación, bloqueos de E/S, y más.

    - "vmstat 1":  Esto actualizará la información cada segundo.

    - "iostat": proporciona estadísticas de uso de CPU y entrada/salida de dispositivos.

    - "journalctl -f": para ver los logs del sistema en tiempo real

## Monitorice en “tiempo real” las conexiones de su sistema.

    - Puedes usar ss / netstat para ver las conexiones de red en tiempo real: "watch -n 1 ss/netstat -tuln"

# L) Un primer nivel de filtrado de servicios los constituyen los tcp-wrappers. 

## Configure el tcp- wrapper de su sistema (basado en los ficheros hosts.allow y hosts.deny) para permitir conexiones SSH a un determinado conjunto de IPs y denegar al resto.

    - host.deny:

        # /etc/hosts.deny: list of hosts that are _not_ allowed to access the system.
        #                  See the manual pages hosts_access(5) and hosts_options(5).
        #
        # Example:    ALL: some.host.name, .some.domain
        #             ALL EXCEPT in.fingerd: other.host.name, .other.domain
        #
        # If you're going to protect the portmapper use the name "rpcbind" for the
        # daemon name. See rpcbind(8) and rpc.mountd(8) for further information.
        #
        # The PARANOID wildcard matches any host whose name does not match its
        # address.
        #
        # You may wish to enable this to ensure any programs that don't
        # validate looked up hostnames still leave understandable logs. In past
        # versions of Debian this has been the default.
        # ALL: PARANOID


        ALL: ALL: twist /bin/echo `/bin/date`\: intento de conexion %a a %A [DENEGADO] >> /var/log/denegados <--(Linea que añadimos)

    - host.allow:

        # /etc/hosts.allow: list of hosts that are allowed to access the system.
        #                   See the manual pages hosts_access(5) and hosts_options(5).
        #
        # Example:    ALL: LOCAL @some_netgroup
        #             ALL: .foobar.edu EXCEPT terminalserver.foobar.edu
        #
        # If you're going to protect the portmapper use the name "rpcbind" for the
        # daemon name. See rpcbind(8) and rpc.mountd(8) for further information.
        #


        sshd: 10.11.51.99: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos
        sshd: 10.11.49.99: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos

        sshd: [2002:ab0:3163::]: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos

        sshd: 127.0.0.1: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos

        sshd: 10.30.0.0/16: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos
        sshd: 10.20.0.0/16: spawn /bin/echo `/bin/date`\: intento de conexión de %a a %A \[PERMITIDO\] >> /var/log/permitidos

## ¿Qué política general de filtrado ha aplicado?.

    - Esto implementa una política de "deny by default" (denegar por defecto), donde todos los accesos no permitidos explícitamente son denegados. Esta es una práctica común en la administración de sistemas para mejorar la seguridad al limitar las conexiones a solo aquellas que son necesarias.

## ¿Es lo mismo el tcp-wrapper que un firewall?.

    - TCP Wrapper es una herramienta de control de acceso que se utiliza para permitir o denegar conexiones a servicios basados en TCP. Actúa como una capa de seguridad en el nivel de la aplicación, proporcionando un método simple para controlar quién puede acceder a ciertos servicios.
    - Un firewall (cortafuegos) es un dispositivo o software que filtra el tráfico de red entre dos redes (por ejemplo, entre una red interna y la Internet) basándose en un conjunto de reglas de seguridad definidas. Puede operar en varios niveles del modelo OSI 

##  Obtenga la relación de servicios que utilizan los wrappers de su sistema.

    - grep -l 'libwrap' /etc/services/* (DISCLAIMER: NO SE SI FUNCIONA)

    1.Buscar en los archivos de configuración de servicios
        1.1.Algunos servicios tienen su propio archivo de configuración.
    2.Busca la línea que haga referencia a TCP Wrappers –> # TCPWrapper yes
        2.1.Si está descomentado, significa que el servicio está utilizando TCP Wrappers


## Deje únicamente registro de los intentos fallidos-no autorizados de acceso en /var/log/denegados incluyendo el nombre de la máquina, nombre del proceso que atiende la conexión e id del proceso, IP de la máquina origen de la conexión, fecha y hora de la misma.

    $FileGroup adm
    $FileCreateMode 0640
    $DirCreateMode 0755
    $Umask 0022

    #
    # Where to place spool and state files
    #
    $WorkDirectory /var/spool/rsyslog

    #
    # Include all config files in /etc/rsyslog.d/
    #
    $IncludeConfig /etc/rsyslog.d/*.conf


    ###############
    #### RULES ####
    ###############

    #
    # Log anything besides private authentication messages to a single log file
    #
    *.*;auth,authpriv.none          -/var/log/syslog

    #
    # Log commonly used facilities to their own log file
    #
    auth,authpriv.*                 /var/log/auth.log
    cron.*                          -/var/log/cron.log
    kern.*                          -/var/log/kern.log
    mail.*                          -/var/log/mail.log
    user.*                          -/var/log/user.log

    if $programname == 'sshd' and $msg contains 'Failed password' then /var/log/denegados
    & stop

    if $programname == 'sshd' and $msg contains 'refused connect' then /var/log/denegados
    & stop

    #
    # Emergencies are sent to everybody logged in.
    #
    *.emerg                         :omusrmsg:*

# M) Existen múltiples paquetes para la gestión de logs (syslog, syslog-ng, rsyslog)

## Utilizando el rsyslog pruebe su sistema de log local

    - Puedes probar rsyslog enviando mensajes manualmente:  "logger "Este es un mensaje de prueba para rsyslog""

    - Este comando mostrará en tiempo real los nuevos mensajes de log: "tail -f /var/log/syslog"

## Pruebe también el journald.

    - Este comando mostrará en tiempo real los logs del sistema: "journalctl -f"
    - Filtrar los logs por servicios específicos, por ejemplo, para ver los logs del servicio ssh: "journalctl -u ssh.service"
    - Ver logs desde el último arranque del sistema: "journalctl -b"

# N) Configure IPv6 6to4 y pruebe ping6 y ssh sobre dicho protocolo

## Configuración

    # This file describes the network interfaces available on your system
    # and how to activate them. For more information, see interfaces(5).
    #source /etc/network/interfaces.d/*
    # The loopback network interface
    auto lo ens33 ens34 6to4
    iface lo inet loopback

    iface ens33 inet static
            address 10.11.49.104/23
            gateway 10.11.48.1
            dns-nameservers 10.8.12.47 10.8.12.49 10.8.12.50
    iface ens34 inet static
            address 10.11.51.104/23
    iface 6to4 inet6 v4tunnel
            address 2002:a0b:3168::
            netmask 16
            endpoint any
            local 10.11.49.104

##  ¿Qué hace su tcp-wrapper en las conexiones ssh en IPv6?

    En el TCP Wrapper (hosts.allow y hosts.deny) se puede config tanto para IPv4 como para IPv6
            Ej:     
                
                # Permitir conexiones SSH desde una dirección IPv6 específica
                sshd: 2001:0db8:1234::5678
                # Denegar todas las demás conexiones SSH IPv6
                sshd: ALL

## Modifique su tcp-wapper siguiendo el criterio del apartado h).

    - Añadir conexiones IPv6 (igual que las otras pero van entre corchetes)

## ¿Necesita IPv6?

    - Depende del contexto (en nuestro caso no es necesaria)

##  ¿Cómo se deshabilita IPv6 en su equipo?

    - Si no necesitamos IPv6 y queremos deshabilitarlo:
        1.Editar /etc/sysctl.conf y agregar lo siguiente:
		    "net.ipv6.conf.all.disable_ipv6 = 1"
		    "net.ipv6.conf.default.disable_ipv6 = 1"
	    2.Este comando para aplicar los cambios
            "sysctl -p"