import os
import shutil
import subprocess


def ejecutar_comando(comando, entrada_texto=None):
    """Ejecuta un comando del sistema y devuelve salida o error."""
    try:
        resultado = subprocess.run(
            comando,
            input=entrada_texto,
            text=True,
            capture_output=True,
            check=True,
        )
        return resultado.stdout.strip(), None
    except FileNotFoundError:
        return None, "No se encontró el ejecutable requerido."
    except subprocess.CalledProcessError as exc:
        return None, exc.stderr.strip() or "Error al ejecutar el comando."


def wg_disponible():
    """Comprueba si el binario 'wg' está disponible en el sistema."""
    return shutil.which("wg") is not None


def iptables_disponible():
    """Comprueba si iptables está disponible en el sistema."""
    return shutil.which("iptables") is not None


def generar_par_claves(registrar_log=None):
    """Genera claves privada y pública usando 'wg' (WireGuard)."""
    if registrar_log:
        registrar_log("Comprobando disponibilidad de WireGuard...")
    if not wg_disponible():
        return None, None, "WireGuard no está instalado o el comando 'wg' no está disponible."

    if registrar_log:
        registrar_log("Generando clave privada...")
    clave_privada, error = ejecutar_comando(["wg", "genkey"])
    if error:
        return None, None, error
    if clave_privada is None:
        return None, None, "No se pudo generar la clave privada."

    if registrar_log:
        registrar_log("Generando clave pública...")
    clave_publica, error = ejecutar_comando(["wg", "pubkey"], entrada_texto=clave_privada + "\n")
    if error:
        return None, None, error

    return clave_privada, clave_publica, None


def ejecutar_comando_con_log(comando, descripcion, registrar_log):
    """Ejecuta un comando y registra todo en el log."""
    registrar_log(descripcion)
    registrar_log(f"Ejecutando: {' '.join(comando)}")
    try:
        resultado = subprocess.run(
            comando,
            text=True,
            capture_output=True,
            check=True,
        )
        if resultado.stdout:
            registrar_log(resultado.stdout.strip())
        if resultado.stderr:
            registrar_log(resultado.stderr.strip())
        return True
    except FileNotFoundError:
        registrar_log("No se encontró el ejecutable requerido para instalar.")
    except subprocess.CalledProcessError as exc:
        registrar_log("Error al ejecutar el comando.")
        if exc.stdout:
            registrar_log(exc.stdout.strip())
        if exc.stderr:
            registrar_log(exc.stderr.strip())
    return False


def comprobar_wireguard(ping_ip, registrar_log):
    """Ejecuta comprobaciones básicas de WireGuard y conectividad."""
    registrar_log("Comprobando estado de WireGuard...")
    comandos = [
        (["wg", "show"], "Salida de wg show"),
        (["ip", "a"], "Interfaces de red (ip a)"),
        (["ip", "route"], "Rutas del sistema (ip route)"),
    ]

    for comando, descripcion in comandos:
        ok = ejecutar_comando_con_log(comando, descripcion, registrar_log)
        if not ok:
            return False, "Falló una comprobación. Revisa el log."

    if ping_ip:
        ok = ejecutar_comando_con_log(
            ["ping", "-c", "4", ping_ip],
            f"Ping a {ping_ip}",
            registrar_log,
        )
        if not ok:
            return False, "El ping no fue exitoso."

    return True, "Comprobaciones finalizadas."


def obtener_prefijo_privilegios(registrar_log):
    """Obtiene el prefijo de privilegios (pkexec/sudo) si es necesario."""
    prefijo = []
    if os.geteuid() != 0:
        if shutil.which("pkexec"):
            prefijo = ["pkexec"]
            registrar_log("Se solicitarán privilegios con pkexec.")
        elif shutil.which("sudo"):
            prefijo = ["sudo"]
            registrar_log("Se solicitarán privilegios con sudo.")
        else:
            registrar_log("No se encontró pkexec ni sudo. Se requieren permisos.")
            return None
    return prefijo


def instalar_wireguard(registrar_log):
    """Instala WireGuard en Debian/Kali usando apt-get."""
    registrar_log("Iniciando instalación automática de WireGuard en Debian/Kali...")
    if wg_disponible():
        registrar_log("WireGuard ya está instalado. No se requiere instalación.")
        return True, "WireGuard ya está instalado."

    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    ok = ejecutar_comando_con_log(
        prefijo + ["apt-get", "update"],
        "Actualizando listas de paquetes...",
        registrar_log,
    )
    if not ok:
        return False, "Fallo al actualizar paquetes."

    ok = ejecutar_comando_con_log(
        prefijo + ["apt-get", "install", "-y", "wireguard"],
        "Instalando paquete wireguard...",
        registrar_log,
    )
    if not ok:
        return False, "Fallo al instalar WireGuard."

    if wg_disponible():
        registrar_log("Instalación finalizada correctamente.")
        return True, "WireGuard se instaló correctamente."

    registrar_log("La instalación terminó, pero 'wg' no se detecta.")
    return False, "Instalación finalizada, pero no se detecta 'wg'."


def activar_interfaz(ruta_config, registrar_log):
    """Levanta una interfaz WireGuard usando wg-quick."""
    registrar_log("Iniciando activación de interfaz con wg-quick...")
    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    ok = ejecutar_comando_con_log(
        prefijo + ["wg-quick", "up", ruta_config],
        "Levantando interfaz con wg-quick...",
        registrar_log,
    )
    if ok:
        return True, "Interfaz activada correctamente."
    return False, "No se pudo activar la interfaz."


def desactivar_interfaz(ruta_config, registrar_log):
    """Baja una interfaz WireGuard usando wg-quick."""
    registrar_log("Iniciando desactivación de interfaz con wg-quick...")
    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    ok = ejecutar_comando_con_log(
        prefijo + ["wg-quick", "down", ruta_config],
        "Bajando interfaz con wg-quick...",
        registrar_log,
    )
    if ok:
        return True, "Interfaz desactivada correctamente."
    return False, "No se pudo desactivar la interfaz."


def habilitar_ip_forwarding(registrar_log):
    """Habilita el reenvío de IPv4 para permitir el enrutamiento."""
    registrar_log("Habilitando IP forwarding (net.ipv4.ip_forward=1)...")
    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    ok = ejecutar_comando_con_log(
        prefijo + ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        "Aplicando sysctl para IP forwarding...",
        registrar_log,
    )
    if ok:
        return True, "IP forwarding habilitado."
    return False, "No se pudo habilitar IP forwarding."


def aplicar_reglas_iptables(interfaz_wg, interfaz_salida, red_interna, registrar_log):
    """Aplica reglas básicas de iptables para NAT y forwarding de WireGuard."""
    registrar_log("Aplicando reglas de iptables para WireGuard...")
    if not iptables_disponible():
        return False, "iptables no está instalado. Usa: sudo apt-get install -y iptables"

    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    reglas = [
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", red_interna, "-o", interfaz_salida, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", interfaz_wg, "-o", interfaz_salida, "-j", "ACCEPT"],
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            interfaz_salida,
            "-o",
            interfaz_wg,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    ]

    for regla in reglas:
        ok = ejecutar_comando_con_log(prefijo + regla, "Aplicando regla iptables...", registrar_log)
        if not ok:
            return False, "No se pudieron aplicar todas las reglas de iptables."

    return True, "Reglas de iptables aplicadas correctamente."


def eliminar_reglas_iptables(interfaz_wg, interfaz_salida, red_interna, registrar_log):
    """Elimina reglas básicas de iptables para NAT y forwarding de WireGuard."""
    registrar_log("Eliminando reglas de iptables para WireGuard...")
    if not iptables_disponible():
        return False, "iptables no está instalado. Usa: sudo apt-get install -y iptables"

    prefijo = obtener_prefijo_privilegios(registrar_log)
    if prefijo is None:
        return False, "Se requieren privilegios de administrador."

    reglas = [
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", red_interna, "-o", interfaz_salida, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", interfaz_wg, "-o", interfaz_salida, "-j", "ACCEPT"],
        [
            "iptables",
            "-D",
            "FORWARD",
            "-i",
            interfaz_salida,
            "-o",
            interfaz_wg,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    ]

    for regla in reglas:
        ok = ejecutar_comando_con_log(prefijo + regla, "Eliminando regla iptables...", registrar_log)
        if not ok:
            return False, "No se pudieron eliminar todas las reglas de iptables."

    return True, "Reglas de iptables eliminadas correctamente."
