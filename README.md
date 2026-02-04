# WireJuardo GUI (Tkinter)
## ESTO TODAVÍA NO HACE LO QUE DEBE

Aplicación gráfica para **instalar, configurar y administrar WireGuard** en Debian, Kali o Ubuntu. Permite generar claves, crear archivos de configuración de cliente/servidor, activar/desactivar interfaces con `wg-quick` y aplicar reglas básicas de `iptables` para NAT.

## Requisitos

- Python 3.8+
- Paquetes del sistema:
  - `wireguard` (opcional si solo vas a generar configs)
  - `iptables` (si vas a configurar NAT)
- Dependencia Python:
  - `Pillow`

Instalación de dependencia:

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
python3 main.py
```

## Funcionalidades

- **Generar claves** (pública/privada) usando `wg`.
- **Crear configuración** cliente y servidor.
- **Guardar .conf** en cualquier ruta.
- **Crear wg0.conf** solicitando los datos y guardando directamente en una carpeta elegida.
- **Instalación automática** de WireGuard (Debian/Kali/Ubuntu).
- **Activar/Desactivar** interfaz con `wg-quick`.
- **Configurar iptables** (NAT + forwarding) desde la pestaña Servidor.
- **Registro de acciones** para saber qué está haciendo el programa.

## Configuración de iptables

En la pestaña **Servidor** encontrarás campos para:

- **Red interna** (ej. `10.0.0.0/24`)
- **Interfaz de salida** (ej. `eth0`)
- **Interfaz WireGuard** (ej. `wg0`)

Con los botones:

- **Aplicar iptables** → añade reglas NAT y habilita IP forwarding.
- **Eliminar iptables** → elimina esas reglas.

> Nota: se requieren privilegios de administrador (sudo/pkexec).

## Dónde colocar los archivos .conf

En Debian/Kali/Ubuntu, WireGuard busca las configuraciones en:

- `/etc/wireguard/<interfaz>.conf` (por ejemplo `/etc/wireguard/wg0.conf`)

Si quieres usar el servicio `wg-quick@wg0`, el archivo debe estar en esa ruta.

El programa permite guardar el archivo en cualquier carpeta y también activar con `wg-quick` usando una ruta directa. Si guardas fuera de `/etc/wireguard`, asegúrate de seleccionar el archivo correcto cuando uses **Activar wg-quick**.

> Nota: para escribir en `/etc/wireguard` se requieren permisos de administrador.


## Estructura del proyecto

```
.
├── configuraciones.py
├── interfaz.py
├── main.py
├── menu_superior.py
├── requirements.txt
├── wireguard_utils.py
└── img/
    └── logo.png
```

## Notas

- Si el navegador falla al abrir el enlace, la app limpia temporalmente `GTK_PATH` para evitar errores con Firefox.

