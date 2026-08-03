<p align="center">
  <img src="assets/cottendns.png" alt="Logotipo de CottenDNS" width="150">
</p>

<h1 align="center">CottenDNS</h1>

<p align="center">
  <strong>Un túnel DNS centrado en velocidad para redes censuradas, inestables y con pérdidas.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licencia MIT" src="https://img.shields.io/badge/license-MIT-16a34a?style=flat-square"></a>
  <a href="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml"><img alt="Compilación" src="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml/badge.svg"></a>
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest"><img alt="Última versión" src="https://img.shields.io/github/v/release/TaJirax/cottenDNS?style=flat-square"></a>
</p>

<p align="center">
  <a href="README.MD">English</a> ·
  <a href="README_FA.MD">فارسی</a> ·
  <a href="README_RU.MD">Русский</a> ·
  <a href="README_ZH.MD">简体中文</a> ·
  <a href="README_ES.MD">Español</a>
</p>

<p align="center">
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest">Descargar</a> ·
  <a href="docs/ENGINEERING_CHANGES.md">Notas de ingeniería</a> ·
  <a href="CONFIG_PRESETS.md">Perfiles</a> ·
  <a href="https://t.me/whitedns">Telegram</a>
</p>

> [!IMPORTANT]
> CottenDNS está diseñado para redes donde los VPN y proxies normales están bloqueados, pero aún existe una ruta DNS utilizable. Un túnel DNS es inherentemente más lento que un VPN normal. El objetivo es obtener la máxima velocidad útil y continuidad bajo censura.

## Empieza aquí

| Objetivo | Sección |
| --- | --- |
| Desplegar un túnel nuevo | [Guía completa](#guía-completa-de-instalación) |
| Entender la selección de transporte | [Comportamiento automático](#comportamiento-automático) |
| Elegir un perfil | [Perfiles](#perfiles) |
| Revisar el servidor | [Monitorización](#monitorización) |
| Integrar el motor Android | [Android y submodule](#android-y-submodule) |

## Origen y créditos

CottenDNS se apoya en el trabajo de dos proyectos:

1. **[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)** de **Amin Mahmoudi** creó la base de bajo overhead, ARQ personalizado, balanceo de resolvers, multiplexación y diseño para redes hostiles.
2. **[StormDNS](https://github.com/nullroute1970/StormDNS)**, mantenido por **NullRoute1970**, es el upstream directo del que deriva CottenDNS.
3. **CottenDNS**, mantenido por **tajirax**, amplía esa base y conserva compatibilidad con clientes MasterDNS/StormDNS.

CottenDNS es un derivado independiente; no afirma haber creado la arquitectura original. Los proyectos conservan el linaje de licencia MIT. Consulta [LICENSE](LICENSE).

## Cómo funciona

```text
Aplicación
   │
   ▼
SOCKS5 / TCP local
   │
   ▼
Cliente CottenDNS
   ├── UDP/53 ─────┐
   ├── TCP/53 ─────┤
   ├── DoT ────────┤──► Resolver DNS ──► Servidor CottenDNS ──► Internet
   └── DoH ────────┘
```

El cliente divide los flujos en tramas pequeñas aptas para DNS, las cifra y comprime opcionalmente, selecciona una ruta de resolver/transporte y repara pérdidas mediante ARQ y FEC Reed–Solomon. El servidor reconstruye los flujos y abre la conexión directamente, mediante un SOCKS5 upstream o hacia un destino TCP fijo.

El SOCKS5 integrado admite TCP y asociaciones UDP genéricas. El servicio DNS local y su caché son opcionales.

## Ventajas principales

| Problema de red | Respuesta de CottenDNS |
| --- | --- |
| UDP es rápido pero puede ser envenenado o limitado | Conserva UDP viable y cambia solamente el resolver afectado |
| Cada resolver se comporta distinto | Evalúa cada `(resolver, transporte)` por separado |
| Subida y bajada tienen distinta calidad | Evidencia direccional separada de entrega, fallos, RTT y confianza |
| MTU DNS pequeño | Descubrimiento por ruta y selección según el tamaño de cada paquete |
| Pérdida severa | ARQ, ACK/NACK, replay inmediato, duplicación adaptativa y FEC |
| Una respuesta falsa llega demasiado rápido | La usa como alerta y compite con una alternativa autenticada |
| Muere una ruta con tramas en vuelo | Reproduce tramas no confirmadas sin recrear la sesión |
| La redundancia congestiona el enlace | FEC, duplicación, replay y exploración comparten un presupuesto |
| Varias rutas son equivalentes | Distribuye tráfico bulk de una sola copia entre rutas maduras |
| DPI reconoce DNS repetitivo | Rotación de registros, forma QNAME, ID/cookies aleatorios y DoT/DoH opcional |

## Comportamiento automático

Valores recomendados:

```toml
CONFIG_PRESET = "speed"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

El cliente automáticamente:

- prueba UDP primero y lo conserva mientras funcione bien;
- compara UDP y TCP/53 para cada resolver;
- cambia únicamente la ruta que falla o es materialmente más lenta;
- considera tamaño, MTU, RTT, pérdida, dirección y confianza;
- mantiene alternativas activas con un presupuesto de fondo mínimo;
- evita acumular FEC, exploración y duplicación innecesaria;
- compite con una alternativa cuando detecta poisoning;
- reproduce tramas en vuelo antes de esperar todo el RTO de ARQ.

`auto` no activa DoT/DoH sin permiso. Son opciones explícitas:

```toml
RESOLVER_TRANSPORT = "dot" # o "doh"
```

Overrides por resolver:

```toml
RESOLVER_TRANSPORT_PATHS = { "1.1.1.1" = "doh", "8.8.8.8" = "auto", "9.9.9.9" = "tcp" }
```

## Servidor dinámico

UDP, TCP/53, DoT y DoH alimentan el mismo motor nativo de sesiones. Con:

```toml
ENCRYPTION_AUTO_DETECT = true
```

el servidor acepta automáticamente los métodos con clave 1–5 elegidos por los clientes. AES-128/192/256-GCM siempre se prueba antes que los decodificadores legacy no autenticados. XOR y ChaCha20 también deben coincidir con una sesión válida o con la semántica estricta de MTU. El método plaintext `0` solo se permite cuando el servidor lo habilita expresamente.

Distintos clientes pueden elegir distintos cifrados, transportes, MTU, compresión y fiabilidad sin reconfigurar el servidor. El servidor sigue aplicando sus límites de seguridad.

## Guía completa de instalación

Flujo habitual:

```text
[Dispositivo cliente] → [resolvers DNS] → [subdominio delegado en el VPS] → [Internet]
```

### Antes de empezar

Necesitas un dominio cuyas entradas DNS puedas editar, un VPS Linux con IPv4 pública y acceso `sudo`, UDP/53 y TCP/53 entrantes permitidos, y un cliente Windows, Linux o macOS. Abre el puerto 53 tanto en el firewall del sistema como en el firewall o grupo de seguridad del proveedor.

> [!CAUTION]
> `systemd-resolved`, BIND, dnsmasq o un panel pueden estar usando el puerto 53. Compruébalo con `sudo ss -lntup | grep ':53 '`. Mantén abierto SSH o tu puerto de administración para no perder acceso al cambiar el firewall.

### Paso 1 — Delega un subdominio corto

Crea estas entradas en el proveedor DNS de `example.com`:

```dns-zone
ns.example.com.  300  IN  A   203.0.113.10
v.example.com.   300  IN  NS  ns.example.com.
```

Sustituye la IP por la IPv4 pública del VPS. No actives el proxy CDN para estas entradas. Un nombre corto deja más espacio útil dentro de cada paquete DNS.

Comprueba la propagación:

```bash
dig +short A ns.example.com
dig +short NS v.example.com
```

Debes recibir la IP del servidor y `ns.example.com.`. Si falta el resultado NS, corrige la delegación antes de configurar el cliente.

### Paso 2 — Instala el servidor

```bash
sudo install -d -m 0755 /opt/cottendns
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash
```

Cuando el instalador pregunte, introduce `v.example.com`. Descargará el release, preparará configuración y clave, instalará el servicio systemd, abrirá UDP/TCP 53 en firewalls compatibles y verificará `/healthz`.

Archivos importantes:

```text
/opt/cottendns/server_config.toml
/opt/cottendns/encrypt_key.txt
```

Copia la clave al cliente mediante un canal seguro:

```bash
sudo cat /opt/cottendns/encrypt_key.txt
```

Nunca publiques la clave en capturas, Issues, configuraciones públicas o listas de resolvers.

### Paso 3 — Verifica el servidor

```bash
systemctl is-active cottendns
curl -fsS http://127.0.0.1:9090/healthz
sudo ss -lnup | grep ':53 '
sudo ss -lntp | grep ':53 '
```

Si falla:

```bash
journalctl -u cottendns -n 100 --no-pager
```

El puerto de monitorización `9090` es local por defecto; no lo expongas directamente a Internet.

### Paso 4 — Configura el cliente

Descarga desde [Releases](https://github.com/TaJirax/cottenDNS/releases/latest) el archivo correspondiente a tu sistema y arquitectura. Conserva el ejecutable, `client_config.toml` y `client_resolvers.txt` en la misma carpeta.

Empieza con esta configuración mínima y segura:

```toml
DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "clave-del-servidor"
DATA_ENCRYPTION_METHOD = 3

PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18000

CONFIG_PRESET = "speed"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

`client_resolvers.txt`:

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

Empieza con una lista pequeña y diversa. Una lista enorme de resolvers deficientes solo alarga el escaneo.

### Paso 5 — Primer escaneo y arranque

Linux:

```bash
chmod +x ./CottenDns_Client_*
./CottenDns_Client_Linux_AMD64_vVERSION --config ./client_config.toml
```

Windows PowerShell:

```powershell
.\CottenDns_Client_Windows_AMD64_vVERSION.exe --config .\client_config.toml
```

El cliente medirá conectividad real del túnel, MTU, latencia, pérdida y rutas UDP/TCP por resolver. Para escanear sin iniciar el proxy, añade `--scan-only`.

Mantén `STARTUP_MODE = "resolvers"` en cada inicio. La conectividad, el
envenenamiento, el transporte y el MTU pueden cambiar entre reinicios.
`FAST_CONNECT = true` permite conectar cuando existe un pequeño pool recién
validado y continúa comprobando los demás resolvers en segundo plano sin confiar
en una caché de procesos anteriores.

### Paso 6 — Prueba SOCKS5

Configura `SOCKS5 127.0.0.1:18000` en la aplicación o ejecuta:

```bash
curl --proxy socks5h://127.0.0.1:18000 https://example.com/
```

`socks5h` hace que la resolución del nombre también viaje por el proxy.

### Actualización segura

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --upgrade
```

La actualización conserva configuración y clave, y revierte si el servicio nuevo no supera el health check. Para el cliente de escritorio, extrae el release nuevo en otra carpeta y conserva el anterior hasta completar el escaneo y la prueba SOCKS.

## Perfiles

| Perfil | Cuándo usarlo |
| --- | --- |
| `speed` | Opción normal para máxima velocidad útil |
| `survival` | Pérdida alta, resolvers inestables o censura agresiva |
| `tcp-survival` | UDP/53 no funciona y TCP/53 sobrevive |
| `iran`, `china`, `russia`, `venezuela`, `cuba` | Puntos de partida para restricciones regionales |
| `low-bandwidth` | Subida muy limitada o presupuesto DNS pequeño |

Son puntos de partida, no detección automática del país. Consulta [CONFIG_PRESETS.md](CONFIG_PRESETS.md).

## Monitorización

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s 'http://127.0.0.1:9090/healthz?details=1' | jq
curl -s http://127.0.0.1:9090/metrics
```

Uso del proceso:

```bash
pid=$(systemctl show -p MainPID --value cottendns)
ps -p "$pid" -o pid,%cpu,%mem,rss,vsz,etime,cmd
top -p "$pid"
```

## Android y submodule

Una aplicación Android puede fijar este repositorio como submodule Git o dependencia de CI. Commit verificado:

```text
8eea49d1267b1a41441c25c75e69e6f12ad0a11f
```

El motor compila sin CGO para Android arm64, armv7, amd64 y 386. La capa Android debe conservar los valores TOML recomendados.

## Compatibilidad y seguridad

- Cliente nuevo + servidor nuevo: todas las funciones.
- Cliente antiguo + servidor nuevo: compatible, incluidos MasterDNS/StormDNS.
- Cliente nuevo + servidor antiguo: mejoras del cliente disponibles, sin las funciones nuevas del servidor.
- Usa AES-GCM `3`, `4` o `5` para cifrado autenticado.
- DoT/DoH protege el tramo cliente→resolver, no todo el recorrido.
- El volumen y temporización todavía pueden revelar un túnel.
- No publiques `encrypt_key.txt`.
- Utiliza el proyecto solo donde estés autorizado.

## Documentación y desarrollo

| Documento | Contenido |
| --- | --- |
| [CONFIG_PRESETS.md](CONFIG_PRESETS.md) | Perfiles de velocidad, supervivencia y región |
| [ENGINEERING_CHANGES.md](docs/ENGINEERING_CHANGES.md) | Arquitectura, correcciones y pruebas |
| [client_config.toml.simple](client_config.toml.simple) | Configuración completa del cliente |
| [server_config.toml.simple](server_config.toml.simple) | Configuración completa del servidor |

```bash
go build ./cmd/client
go build ./cmd/server
go test ./...
go vet ./...
```

## Licencia y agradecimientos

CottenDNS es mantenido por **tajirax** y se distribuye bajo la [Licencia MIT](LICENSE).

- **Amin Mahmoudi** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN), arquitectura original.
- **NullRoute1970** — [StormDNS](https://github.com/nullroute1970/StormDNS), upstream directo.
- Gracias a todos los colaboradores, testers y usuarios que reportan condiciones reales de redes censuradas.
