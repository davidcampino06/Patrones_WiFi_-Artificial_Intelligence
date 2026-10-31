# Agente WiFiSense

Programa que corre en un computador de tu casa, mide la red Wi-Fi y envía un reporte a WiFiSense cada 5 minutos.
Con esos reportes la IA te dice **cuántos equipos están conectados**, si apareció uno nuevo, qué tan segura es tu red
(auditoría de seguridad) y si hay anomalías en la conexión.

El mismo programa es el **sensor de las redes del equipo**: en el panel, **Redes → (la red) → Conectar sensor** muestra
un código de 8 caracteres; se instala igual, en un computador conectado a esa red, y desde entonces sus reportes son
las mediciones reales de esa red (latencia, pérdida, señal, velocidad del enlace, equipos y tráfico). Desde 1.5.0 el
panel muestra además, como Mi Wi-Fi, los equipos conectados (fabricante y nombre), la auditoría de seguridad y el mejor
canal. El código decide para cuál red trabaja: uno de Mi Wi-Fi la conecta con la casa del usuario; uno del panel, con
la red del equipo.

**Varias redes en un mismo computador (1.6.0).** Cada código queda ligado al Wi-Fi al que estaba conectado el
computador cuando se instaló. Se pueden agregar los códigos de varias redes (por ejemplo los dos Wi-Fi de una casa, o
la casa y la universidad): en cada reporte el agente mira a qué Wi-Fi está conectado y usa la clave de esa red, así
que al cambiar de Wi-Fi cambia de red solo. En un Wi-Fi sin código no envía nada, para no guardar sus mediciones como
si fueran de otra red; el tráfico tampoco se mezcla entre redes. Una clave revocada desde la página se quita de este
computador y las demás siguen. Una instalación anterior (una sola clave, sin Wi-Fi) sigue funcionando y aprende su
Wi-Fi en el primer reporte.

**Reconocer cada equipo (1.7.0).** Muchos celulares usan una MAC aleatoria y no dan su nombre, así que la lista
decía «Equipo desconocido». Ahora el agente también escucha lo que los equipos **anuncian de sí mismos** en la red y
mira qué servicios ofrecen, y con eso deduce qué son:

- **mDNS / Bonjour**: los iPhone, Mac, Chromecast, impresoras, parlantes y televisores anuncian su nombre
  («iPhone de Ana», «Sala TV») y a veces su modelo («MacBookPro18,1», «Chromecast»).
- **UPnP / SSDP**: televisores, consolas, decodificadores y routers publican una descripción con fabricante y modelo.
  El agente la lee solo de la misma IP que la anunció y solo en la red local.
- **Servicios**: un equipo que atiende el puerto 62078 es un iPhone o iPad; el 8009, un Chromecast o TV; el 9100, una
  impresora; el 554, una cámara; el 445, un computador con Windows.

Con eso cada equipo llega con su **tipo** (celular, computador, TV, impresora, cámara, parlante, consola o dispositivo
inteligente; es una suposición), su modelo si lo anuncia, y dos marcas seguras: **«Este computador»** (donde corre el
agente) y **«Router»** (la puerta de enlace). Si aun así no sabes cuál es tu celular, la página tiene el asistente
**«¿Cuál es este equipo?»**: durante 10 minutos el agente reporta cada minuto en vez de cada 5; apagas el Wi-Fi del
celular, la página ve cuál desapareció, lo enciendes, ve cuál volvió y le pones nombre.

**El nombre que cada equipo dice al conectarse (1.8.0).** Al entrar a la red, cada equipo pide su dirección con un
mensaje DHCP a toda la red que incluye el nombre que tiene configurado («Galaxy-A54-de-Ana», «DESKTOP-7Q2M»): es de
donde el router saca su lista de equipos conectados. El agente ahora **escucha esos mensajes** (no responde ni pide
nada), recuerda el nombre de cada equipo y lo envía con su huella; la MAC sigue sin salir del computador. Además, la
clase que acompaña la solicitud («android-dhcp-14», «MSFT 5.0») ayuda a saber si es un Android o un Windows.

- **Windows pregunta una vez** si permite que WiFiSenseAgente reciba conexiones: hay que elegir **Permitir** (en una
  red pública, marcar también «Redes públicas»). Si se niega, el agente sigue funcionando sin esta fuente.
- **Solo ve a los equipos que se conectan mientras el agente está abierto**: un celular que ya estaba conectado aparece
  con nombre la próxima vez que se reconecte (al salir y volver, o al apagar y encender su Wi-Fi). El backend guarda el
  nombre aprendido, así que no se pierde.
- **Las redes con aislamiento de clientes** (muchas redes de universidades, hoteles y cafés) no dejan pasar los mensajes
  de un equipo a otro: ahí solo el router conoce los nombres. Los celulares con «dirección privada» y sin nombre
  configurado tampoco dicen uno. Para esos equipos queda **«¿Cuál es este equipo?»** y el lápiz para nombrarlos.

**Redes Wi-Fi cercanas (1.9.0).** En Mi Wi-Fi → **Redes cercanas**, el botón **«Escanear ahora»** le pide al agente
que mire qué redes alcanza a ver la antena de su computador; además el servidor pide un escaneo cada hora con el
reporte. Entre reportes, el agente pregunta cada 30 segundos si alguien pidió escanear, así el botón responde en menos
de un minuto. De cada punto de acceso (BSSID) llega el nombre de la red, la señal, el canal, la banda, el tipo de radio
y la seguridad que anuncia.

- **Cómo:** en Windows le pide al sistema un escaneo nuevo (`WlanScan` de `wlanapi.dll`, sin permisos de administrador
  ni nada que instalar) y unos segundos después lee `netsh wlan show networks mode=bssid`; si Windows no acepta el
  escaneo nuevo, lee la última lista que tenga y la página lo dice («lista que ya tenía el sistema»). En Linux usa
  `nmcli dev wifi list --rescan yes`. Los comandos se ejecutan con sus argumentos por separado, nunca con el shell, y
  con 20 segundos de límite.
- **Lo que no se inventa:** si el sistema no da un dato (Windows 10 no dice la banda; ninguno da la señal en dBm con
  `netsh`), queda vacío. La banda solo se deduce del canal cuando el canal es de 2,4 GHz o de 5 GHz.
- **Privacidad:** el BSSID tampoco sale del computador: se envía su huella con la misma sal de los equipos y solo su
  último byte («termina en …:F1»), para que reconozcas tu router por la etiqueta. El fabricante se envía solo si el
  BSSID es el de fábrica. Nunca se leen ni se exportan las contraseñas de los perfiles Wi-Fi.
- **Ver una red no la hace tuya:** son solo las redes que la antena alcanzó a oír en ese momento (no todas las que
  existen), y verlas no da permiso de conectarse ni de administrarlas.
- **Cuando no se puede**, el escaneo falla con su motivo y la página lo explica: no hay adaptador Wi-Fi
  (`NO_ADAPTER`), el Wi-Fi está apagado (`ADAPTER_OFF`), el servicio de Wi-Fi de Windows está detenido
  (`SERVICE_OFF`), falta el permiso de ubicación de Windows 11 (`LOCATION_PERMISSION`), el comando falló o tardó
  (`COMMAND_FAILED`, `TIMEOUT`), la respuesta no se entendió (`UNREADABLE_OUTPUT`) o el sistema no tiene una
  herramienta conocida (`UNSUPPORTED_OS`, por ejemplo macOS). Si el agente no entrega en 3 minutos, el servidor lo
  marca `AGENT_NO_RESPONSE`.
- **El servidor solo puede pedir un escaneo por su número**: el agente nunca ejecuta órdenes que lleguen del servidor.

Prueba manual en un computador real (no envía nada):

```cmd
WiFiSenseAgente.exe nearby --output cercanas.json
python wifisense_agent.py nearby
```

Muestra cada red con su señal, canal, banda y seguridad, y `cercanas.json` es exactamente lo que se enviaría (sin
ninguna MAC). En GitHub Actions el instalador se prueba igual en Windows real: la máquina no tiene Wi-Fi, así que el
escaneo debe terminar con un motivo conocido y sin ninguna MAC en el archivo.

El código está en `agent/wifi_scan.py` (con `NetshScanner` y `NmcliScanner`, dos estrategias intercambiables que
devuelven el mismo resultado) y la forma de leer los textos de `netsh`/`nmcli`, que comparten la medición y el
escaneo, en `agent/wifi_text.py`.

**Nombres de los equipos: de dónde salen (2.0.0).** Además de lo que el equipo anuncia (mDNS, UPnP, NetBIOS, DHCP), el
agente le pregunta el nombre de cada IP **directamente al DNS del router** (`router_sources.py`): muchos routers
(dnsmasq: TP-Link, ASUS, OpenWrt y varios del operador) responden el nombre que cada equipo dio al pedir dirección.
No usa la clave del router. Cada nombre va con su origen (`nameSource`): `ANNOUNCED` (lo dijo el equipo), `ROUTER` (lo
dijo el router), `CONFIRMED` (el equipo y el router dicen lo mismo) o `DNS` (lo dijo la red). El fabricante por la MAC
es una estimación y nunca se presenta como el nombre.

**Redes grandes (2.0.0).** Hasta la 1.9 el agente suponía que la red era /24 y no veía a un compañero con una IP fuera
de ese pedazo (por ejemplo 10.20.5.40 y 10.20.7.12 en una red /21 de la universidad). Ahora lee la máscara real
(`ipconfig` en cualquier idioma o `ip addr`) y, para no inundar una red enorme, despierta como mucho las 1022
direcciones de alrededor (/22). Si la red tiene **aislamiento de clientes** (común en universidades), ningún equipo
ve a los demás y solo el router los conoce: eso no lo resuelve ningún agente.

**El router no se administra desde WiFiSense.** La lista oficial de clientes, bloquear un equipo o cambiar la
contraseña necesitan la clave del router y una integración por modelo; hoy no existe ninguna, así que no se pide ni se
guarda esa clave. `router_sources.py` deja la abstracción lista (`RouterSource`, `source_for`) para agregar una
integración oficial más adelante sin tocar el resto del agente.

**Actualizar sin código (1.7.0).** Si el programa descargado es más nuevo que el instalado, la ventana muestra
**«Actualizar a la versión X»**: detiene el agente, reemplaza el programa y lo vuelve a iniciar. Las claves y las redes
ya agregadas se conservan; no hace falta ningún código.

## Instalación en Windows (sin Python)

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar agente**. La página muestra un código de 8
   caracteres (sirve 15 minutos y una sola vez) y el botón **Descargar instalador**.
2. Abre `WiFiSenseAgente.exe`. Como es un programa nuevo sin firma digital, Windows puede mostrar «Windows protegió
   su PC»: pulsa **Más información → Ejecutar de todas formas**.
3. La ventana explica qué hace el agente. Escribe el código, deja marcada (o no) la opción de iniciar con Windows y
   pulsa **Instalar**. En segundos aparecen los datos en Mi Wi-Fi (o en el panel del sensor).
4. Para agregar otra red no hay que descargarlo otra vez: conecta el computador a ese Wi-Fi, abre el mismo programa,
   pulsa **Agregar otra red (código)** y escribe el código de esa red.

**Reinstalar con el agente en marcha (1.5.0).** El programa de PyInstaller corre como dos procesos y los dos
mantienen abierto el `.exe`; hasta 1.4.0 el instalador detenía solo uno y Windows no dejaba reemplazar el programa
(«WinError 32 … está siendo utilizado por otro proceso»). Además gastaba el código antes de copiar, así que el
siguiente intento decía «El código no es válido o ya venció». Ahora detiene todos los procesos que corren desde el
programa instalado (nunca el propio instalador), espera a que Windows suelte el archivo, copia y solo entonces usa el
código. Si algo falla, el agente que ya estaba sigue midiendo su red.

Qué queda en el computador, todo a la vista y para el usuario actual (no pide permisos de administrador):

| Dónde | Qué |
|---|---|
| `%LOCALAPPDATA%\Programs\WiFiSense\WiFiSenseAgente.exe` | El programa |
| `%APPDATA%\WiFiSense\agent.json` | La clave del agente y la sal de las huellas (solo para tu usuario) |
| `%LOCALAPPDATA%\WiFiSense\agente.log` | Lo que hace el agente en segundo plano (máximo 1 MB) |
| Administrador de tareas → Aplicaciones de inicio | «WiFiSenseAgente», si elegiste iniciar con Windows (se puede desactivar ahí) |
| Configuración → Aplicaciones → Aplicaciones instaladas | «Agente WiFiSense» con **Desinstalar**, que borra todo lo anterior |

El instalador se construye en GitHub Actions (`.github/workflows/agente-windows.yml`, PyInstaller) cada vez que
cambia la carpeta `agent/` en `main`, y se publica en la versión `agente` del repositorio.

## Uso con Python (desarrollo o Linux)

La página de WiFiSense solo ofrece el instalador de Windows, para que nadie tenga que abrir CMD. El script sigue
siendo el mismo agente (el instalador se construye a partir de él) y se puede usar directo, por ejemplo en Linux o
para probar cambios. Solo necesita **Python 3.9 o superior**; no instala nada más.

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar el agente** y anota el código.
2. Descarga `agent/wifisense_agent.py` de este repositorio.
3. En la carpeta donde lo descargaste:

```cmd
python wifisense_agent.py pair K7QM-4RZD
python wifisense_agent.py scan
python wifisense_agent.py run
```

`pair` cambia el código por la clave del agente y la guarda solo para tu usuario (`%APPDATA%\WiFiSense\agent.json` en Windows,
`~/.config/WiFiSense/agent.json` en Linux). `scan` mide y muestra exactamente lo que se enviaría, sin enviar nada.
`run` envía un reporte cada 5 minutos hasta que pulses Ctrl + C (`run --once` envía uno solo).

Si Windows no deja leer los datos del Wi-Fi: Configuración → Privacidad y seguridad → Ubicación → activa
"Permitir que las aplicaciones de escritorio accedan a tu ubicación" (Windows 11 lo exige para `netsh wlan`).

## Qué mide

| Dato | Cómo |
|---|---|
| Nombre de la red, seguridad, cifrado, señal, canal, banda | `netsh wlan show interfaces` (Windows) o `nmcli` (Linux) |
| Redes vecinas por canal (para recomendar el mejor) | `netsh wlan show networks mode=bssid` o `nmcli` |
| Latencia, jitter y pérdida hacia internet | 10 conexiones TCP a 1.1.1.1:443 |
| Latencia hacia el router | 5 conexiones TCP al router |
| Equipos conectados | un datagrama vacío a cada dirección de la red para llenar la tabla ARP y luego `arp -a` |
| Fabricante de cada equipo | primeros 3 bytes de la MAC (OUI) en una tabla de ~180 fabricantes comunes |
| Nombre de cada equipo | DNS inverso, NetBIOS (Windows) y mDNS/Bonjour (iPhone, Mac, Chromecast, impresoras) |
| Nombre que dice cada equipo al pedir dirección (desde 1.8.0) | mensajes DHCP de la red (puerto 67, solo se escuchan) |
| Tipo y modelo de cada equipo (desde 1.7.0) | servicios mDNS que anuncia, descripción UPnP (SSDP) y algunos puertos típicos (62078 iPhone, 8009 TV, 9100 impresora, 554 cámara…). Se revisa como máximo cada 30 minutos, o antes si aparece un equipo nuevo |
| MAC privada | bit de «administración local»: celulares y tabletas que usan una MAC aleatoria en cada red |
| Puertos abiertos en el router | intento de conexión a 21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080 y 8443 |
| Tráfico de este computador (desde 1.4.0) | contadores del sistema desde el reporte anterior: bytes y paquetes de la tarjeta Wi-Fi (o de cable) y paquetes TCP, UDP e ICMP. En Windows con la API IP Helper (`GetIfTable2`, `GetTcpStatisticsEx`…), igual en cualquier idioma; en Linux de `/proc/net/dev` y `/proc/net/snmp`. No se instala ningún programa de captura |

## Qué es seguro y qué es una suposición

El agente ve la red desde un computador conectado a ella, no desde el router. Por eso no todo lo que muestra tiene la
misma certeza:

| Qué | Certeza | Por qué |
|---|---|---|
| Redes Wi-Fi vecinas y su canal | **Medido** | Las detecta la tarjeta Wi-Fi del computador (`netsh` / `nmcli`) |
| Latencia, jitter, pérdida, señal, tráfico de este computador | **Medido** | Conexiones reales y contadores del sistema |
| Equipos que respondieron en la red local | **Medido, pero incompleto** | Están en la tabla ARP después del barrido. Un equipo dormido o que no responde puede faltar, y uno que acaba de salir puede seguir unos minutos |
| «Este computador» y «Router» | **Seguro** | Son la IP del propio agente y la puerta de enlace del sistema |
| Fabricante | **Deducido** de la MAC (OUI) | Dice quién fabricó la tarjeta, no qué equipo es ni de quién es; con MAC privada no se puede saber |
| Nombre y modelo | **Lo que el equipo anuncia** (mDNS, UPnP, NetBIOS) | Lo eligió su dueño o el fabricante; un equipo puede anunciar cualquier nombre |
| Tipo (celular, TV, impresora…) | **Suposición** | Sale del nombre, los servicios y los puertos que ofrece; la página lo muestra como «Parece…» |
| Equipos confirmados por el router | **No disponible** | Solo el router sabe con certeza quién está conectado, y los routers de la casa y de la sede no ofrecen una API ni SNMP |

Por eso existe el asistente **«¿Cuál es este equipo?»**: confirmar un equipo apagando su Wi-Fi es más fiable que
cualquier suposición. WiFiSense nunca expulsa, bloquea ni interfiere equipos: para sacar a alguien de la red hay que
cambiar la clave del Wi-Fi o bloquearlo en el router, y la página explica cómo.

## Privacidad y seguridad

- Las direcciones MAC **no salen del computador**: se envía una huella SHA-256 con una sal aleatoria creada en esta
  instalación. Sirve para saber si un equipo es nuevo, pero no para saber cuál es.
- De cada equipo se envía el fabricante, el nombre y el modelo que **él mismo anuncia** en la red (como en la lista
  de Bluetooth) y el tipo que el agente deduce, para que lo reconozcas. No se envían IP ni el nombre del usuario del
  computador.
- Para reconocer los equipos el agente solo pregunta lo que cualquier celular pregunta al buscar un Chromecast
  (mDNS y SSDP) e intenta abrir unos pocos puertos de los equipos de la red local, sin enviarles nada.
- La clave solo viaja por HTTPS (el agente rechaza `http://` salvo `localhost`, para pruebas). En el servidor se
  guarda solo su SHA-256; si la pierdes o se filtra, revócala en Mi Wi-Fi → Agente y crea otra.
- El agente no ataca ni cambia nada: solo lee datos del sistema e intenta conexiones normales.
- Del tráfico solo se envían **totales** (cuántos bytes y paquetes, y de qué protocolo), nunca a dónde ni qué
  contenía. Es el tráfico de ese computador, no el de toda la red (eso solo lo ve el router), y solo se guarda cuando
  el agente es el sensor de una red del equipo. Los contadores del último envío quedan en
  `%APPDATA%\WiFiSense\traffic.json`.

Variables opcionales: `WIFISENSE_AGENT_KEY` y `WIFISENSE_SERVER` reemplazan lo guardado por `pair` (o por `setup`, que acepta una clave larga de versiones anteriores).
