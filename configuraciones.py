import os
from tkinter import filedialog


def construir_config_servidor(valores):
    """Crea el contenido del archivo .conf para el servidor."""
    direccion = valores["direccion"]
    puerto_escucha = valores["puerto_escucha"]
    clave_privada = valores["clave_privada"]
    clave_publica_peer = valores["clave_publica_peer"]
    ips_permitidas_peer = valores["ips_permitidas_peer"]

    lineas = ["[Interface]"]
    if direccion:
        lineas.append(f"Address = {direccion}")
    if puerto_escucha:
        lineas.append(f"ListenPort = {puerto_escucha}")
    if clave_privada:
        lineas.append(f"PrivateKey = {clave_privada}")

    # Sección del cliente (peer)
    if clave_publica_peer or ips_permitidas_peer:
        lineas.append("")
        lineas.append("[Peer]")
        if clave_publica_peer:
            lineas.append(f"PublicKey = {clave_publica_peer}")
        if ips_permitidas_peer:
            lineas.append(f"AllowedIPs = {ips_permitidas_peer}")

    return "\n".join(lineas) + "\n"


def construir_config_cliente(valores):
    """Crea el contenido del archivo .conf para el cliente."""
    direccion = valores["direccion"]
    clave_privada = valores["clave_privada"]
    dns = valores["dns"]
    clave_publica_peer = valores["clave_publica_peer"]
    endpoint = valores["endpoint"]
    ips_permitidas = valores["ips_permitidas"]
    keepalive = valores["keepalive"]

    lineas = ["[Interface]"]
    if direccion:
        lineas.append(f"Address = {direccion}")
    if clave_privada:
        lineas.append(f"PrivateKey = {clave_privada}")
    if dns:
        lineas.append(f"DNS = {dns}")

    lineas.append("")
    lineas.append("[Peer]")
    if clave_publica_peer:
        lineas.append(f"PublicKey = {clave_publica_peer}")
    if endpoint:
        lineas.append(f"Endpoint = {endpoint}")
    if ips_permitidas:
        lineas.append(f"AllowedIPs = {ips_permitidas}")
    if keepalive:
        lineas.append(f"PersistentKeepalive = {keepalive}")

    return "\n".join(lineas) + "\n"


def validar_campos(valores, requeridos):
    """Devuelve una lista con los campos requeridos que están vacíos."""
    faltantes = [campo for campo in requeridos if not valores.get(campo)]
    return faltantes


def seleccionar_directorio(registrar_log):
    """Solicita al usuario un directorio para guardar wg0.conf."""
    registrar_log("Solicitando directorio para guardar wg0.conf...")
    ruta = filedialog.askdirectory(title="Seleccionar directorio para wg0.conf")
    if not ruta:
        registrar_log("Selección de directorio cancelada por el usuario.")
        return None
    registrar_log(f"Directorio seleccionado: {ruta}")
    return ruta


def escribir_archivo(ruta, contenido, registrar_log):
    """Escribe el contenido en la ruta indicada."""
    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write(contenido)
    registrar_log(f"Archivo guardado en: {ruta}")


def guardar_configuracion(contenido, nombre_por_defecto, registrar_log):
    """Guarda el contenido en un archivo .conf seleccionado por el usuario."""
    registrar_log("Solicitando ruta para guardar la configuración...")
    ruta = filedialog.asksaveasfilename(
        title="Guardar configuración",
        defaultextension=".conf",
        filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
        initialfile=nombre_por_defecto,
    )
    if not ruta:
        registrar_log("Guardado cancelado por el usuario.")
        return None
    escribir_archivo(ruta, contenido, registrar_log)
    return ruta


def crear_wg0_conf(contenido, registrar_log):
    """Crea el archivo wg0.conf en un directorio elegido por el usuario."""
    directorio = seleccionar_directorio(registrar_log)
    if not directorio:
        return None
    ruta = os.path.join(directorio, "wg0.conf")
    escribir_archivo(ruta, contenido, registrar_log)
    return ruta
