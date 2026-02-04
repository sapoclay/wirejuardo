import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from configuraciones import (
    construir_config_servidor,
    crear_wg0_conf,
    guardar_configuracion,
    validar_campos,
)
from ui_helpers import Tooltip, agregar_entrada_etiquetada
from wireguard_utils import (
    aplicar_reglas_iptables,
    eliminar_reglas_iptables,
    generar_par_claves,
    habilitar_ip_forwarding,
    iptables_disponible,
)


def crear_pestana_servidor(cuaderno, registrar_log):
    """Pestaña con formularios para configurar el servidor."""
    marco = ttk.Frame(cuaderno, padding=10)
    cuaderno.add(marco, text="Servidor")

    entradas = {}
    entradas["nombre_interfaz"] = agregar_entrada_etiquetada(marco, 0, "Nombre de interfaz (ej: wg0)")
    Tooltip(entradas["nombre_interfaz"], "Nombre de la interfaz WireGuard.")
    entradas["direccion"] = agregar_entrada_etiquetada(marco, 1, "Address (ej: 10.0.0.1/24)")
    Tooltip(entradas["direccion"], "IP y máscara de la interfaz del servidor.")
    entradas["puerto_escucha"] = agregar_entrada_etiquetada(marco, 2, "ListenPort (ej: 51820)")
    Tooltip(entradas["puerto_escucha"], "Puerto UDP de escucha del servidor.")
    entradas["clave_privada"] = agregar_entrada_etiquetada(marco, 3, "PrivateKey")
    Tooltip(entradas["clave_privada"], "Clave privada del servidor.")
    entradas["clave_publica_peer"] = agregar_entrada_etiquetada(marco, 4, "PublicKey del cliente")
    Tooltip(entradas["clave_publica_peer"], "Clave pública del cliente.")
    entradas["ips_permitidas_peer"] = agregar_entrada_etiquetada(
        marco, 5, "AllowedIPs del cliente (ej: 10.0.0.2/32)"
    )
    Tooltip(entradas["ips_permitidas_peer"], "IPs permitidas para el cliente.")

    ttk.Separator(marco, orient="horizontal").grid(row=6, column=0, columnspan=2, sticky="ew", pady=6)
    ttk.Label(marco, text="Configuración de iptables (NAT)").grid(
        row=7, column=0, columnspan=2, sticky="w", padx=6
    )

    entradas["red_interna"] = agregar_entrada_etiquetada(
        marco, 8, "Red interna (ej: 10.0.0.0/24)"
    )
    Tooltip(entradas["red_interna"], "Red del túnel usada para NAT.")
    entradas["interfaz_salida"] = agregar_entrada_etiquetada(
        marco, 9, "Interfaz de salida (ej: eth0)"
    )
    Tooltip(entradas["interfaz_salida"], "Interfaz con salida a Internet.")
    entradas["interfaz_wg"] = agregar_entrada_etiquetada(
        marco, 10, "Interfaz WireGuard (ej: wg0)"
    )
    Tooltip(entradas["interfaz_wg"], "Nombre de la interfaz WireGuard.")

    def al_generar_claves():
        registrar_log("Iniciando generación de claves para servidor...")
        clave_privada, clave_publica, error = generar_par_claves(registrar_log)
        if error:
            registrar_log(f"Error al generar claves: {error}")
            messagebox.showerror("Error", error)
            return
        if clave_privada is None or clave_publica is None:
            registrar_log("No se pudieron generar las claves.")
            messagebox.showerror("Error", "No se pudieron generar las claves.")
            return
        entradas["clave_privada"].delete(0, tk.END)
        entradas["clave_privada"].insert(0, clave_privada)
        registrar_log("Clave privada insertada en el formulario.")
        raiz = marco.winfo_toplevel()
        raiz.clipboard_clear()
        raiz.clipboard_append(clave_publica)
        registrar_log("Clave pública copiada al portapapeles.")
        directorio = filedialog.askdirectory(title="Seleccionar carpeta para guardar claves")
        entrada_nombre = entradas.get("nombre_interfaz")
        nombre_interfaz = (entrada_nombre.get().strip() if entrada_nombre else "") or "wg0"
        if not directorio:
            registrar_log("Guardado de claves cancelado por el usuario.")
            registrar_log(
                "No se guardaron archivos: "
                f"{nombre_interfaz}.privkey, {nombre_interfaz}.pubkey"
            )
            messagebox.showinfo(
                "Clave pública",
                "Clave pública copiada al portapapeles:\n\n" + clave_publica,
            )
            return
        ruta_privada = os.path.join(directorio, f"{nombre_interfaz}.privkey")
        ruta_publica = os.path.join(directorio, f"{nombre_interfaz}.pubkey")
        try:
            with open(ruta_privada, "w", encoding="utf-8") as archivo_privado:
                archivo_privado.write(clave_privada + "\n")
            with open(ruta_publica, "w", encoding="utf-8") as archivo_publico:
                archivo_publico.write(clave_publica + "\n")
            registrar_log(f"Clave privada guardada en: {ruta_privada}")
            registrar_log(f"Clave pública guardada en: {ruta_publica}")
            messagebox.showinfo(
                "Claves guardadas",
                "Clave pública copiada al portapapeles y claves guardadas en:\n"
                f"{ruta_privada}\n{ruta_publica}",
            )
        except OSError as exc:
            registrar_log(f"Error al guardar claves: {exc}")
            messagebox.showerror("Error", f"No se pudieron guardar las claves:\n{exc}")
        messagebox.showinfo(
            "Clave pública",
            "Clave pública copiada al portapapeles:\n\n" + clave_publica,
        )

    def al_previsualizar():
        registrar_log("Generando previsualización de la configuración del servidor...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        contenido = construir_config_servidor(valores)
        vista_previa.delete("1.0", tk.END)
        vista_previa.insert(tk.END, contenido)

    def al_guardar():
        registrar_log("Guardando configuración del servidor...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        contenido = construir_config_servidor(valores)
        nombre = f"{valores.get('nombre_interfaz') or 'wg0'}.conf"
        ruta, error = guardar_configuracion(contenido, nombre, registrar_log)
        if ruta:
            messagebox.showinfo("Guardado", f"Configuración guardada en:\n{ruta}")
        elif error:
            messagebox.showerror("Guardado", f"No se pudo guardar la configuración:\n{error}")

    def al_crear_wg0():
        registrar_log("Creando wg0.conf para servidor...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        faltantes = validar_campos(valores, ["direccion", "puerto_escucha", "clave_privada"])
        if faltantes:
            mensaje = "Faltan campos: " + ", ".join(faltantes)
            registrar_log(mensaje)
            messagebox.showerror("Datos incompletos", mensaje)
            return
        contenido = construir_config_servidor(valores)
        ruta, error = crear_wg0_conf(contenido, registrar_log)
        if ruta:
            messagebox.showinfo("wg0.conf", f"Archivo creado en:\n{ruta}")
        elif error:
            messagebox.showerror("wg0.conf", f"No se pudo crear el archivo:\n{error}")

    acciones = ttk.Frame(marco)
    acciones.grid(row=11, column=0, columnspan=2, sticky="w", pady=(4, 8))
    btn_gen = ttk.Button(acciones, text="Generar claves", command=al_generar_claves)
    btn_gen.pack(side="left", padx=4)
    Tooltip(btn_gen, "Genera claves usando wg.")
    btn_prev = ttk.Button(acciones, text="Previsualizar", command=al_previsualizar)
    btn_prev.pack(side="left", padx=4)
    Tooltip(btn_prev, "Muestra el archivo de configuración.")
    btn_guardar = ttk.Button(acciones, text="Guardar", command=al_guardar)
    btn_guardar.pack(side="left", padx=4)
    Tooltip(btn_guardar, "Guarda el archivo .conf.")
    btn_wg0 = ttk.Button(acciones, text="Crear wg0.conf", command=al_crear_wg0)
    btn_wg0.pack(side="left", padx=4)
    Tooltip(btn_wg0, "Crea wg0.conf en una carpeta seleccionada.")

    def al_aplicar_iptables():
        registrar_log("Aplicando configuración de iptables...")
        if not iptables_disponible():
            mensaje = "iptables no está instalado. Usa: sudo apt-get install -y iptables"
            registrar_log(mensaje)
            messagebox.showwarning("iptables", mensaje)
            return
        interfaz_wg = (entradas["interfaz_wg"].get().strip() or entradas["nombre_interfaz"].get().strip())
        interfaz_salida = entradas["interfaz_salida"].get().strip()
        red_interna = entradas["red_interna"].get().strip()
        faltantes = validar_campos(
            {
                "interfaz_wg": interfaz_wg,
                "interfaz_salida": interfaz_salida,
                "red_interna": red_interna,
            },
            ["interfaz_wg", "interfaz_salida", "red_interna"],
        )
        if faltantes:
            mensaje = "Faltan campos: " + ", ".join(faltantes)
            registrar_log(mensaje)
            messagebox.showerror("Datos incompletos", mensaje)
            return

        ok, mensaje = habilitar_ip_forwarding(registrar_log)
        if not ok:
            messagebox.showerror("IP forwarding", mensaje)
            return

        ok, mensaje = aplicar_reglas_iptables(interfaz_wg, interfaz_salida, red_interna, registrar_log)
        if ok:
            messagebox.showinfo("iptables", mensaje)
        else:
            messagebox.showerror("iptables", mensaje)

    def al_eliminar_iptables():
        registrar_log("Eliminando configuración de iptables...")
        interfaz_wg = (entradas["interfaz_wg"].get().strip() or entradas["nombre_interfaz"].get().strip())
        interfaz_salida = entradas["interfaz_salida"].get().strip()
        red_interna = entradas["red_interna"].get().strip()
        faltantes = validar_campos(
            {
                "interfaz_wg": interfaz_wg,
                "interfaz_salida": interfaz_salida,
                "red_interna": red_interna,
            },
            ["interfaz_wg", "interfaz_salida", "red_interna"],
        )
        if faltantes:
            mensaje = "Faltan campos: " + ", ".join(faltantes)
            registrar_log(mensaje)
            messagebox.showerror("Datos incompletos", mensaje)
            return
        ok, mensaje = eliminar_reglas_iptables(interfaz_wg, interfaz_salida, red_interna, registrar_log)
        if ok:
            messagebox.showinfo("iptables", mensaje)
        else:
            messagebox.showerror("iptables", mensaje)

    btn_ipt = ttk.Button(acciones, text="Aplicar iptables", command=al_aplicar_iptables)
    btn_ipt.pack(side="left", padx=4)
    Tooltip(btn_ipt, "Aplica reglas NAT y habilita IP forwarding.")
    btn_ipt_del = ttk.Button(acciones, text="Eliminar iptables", command=al_eliminar_iptables)
    btn_ipt_del.pack(side="left", padx=4)
    Tooltip(btn_ipt_del, "Elimina las reglas aplicadas.")

    vista_previa = tk.Text(marco, height=10, width=72)
    vista_previa.grid(row=12, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)

    marco.columnconfigure(1, weight=1)
    marco.rowconfigure(12, weight=1)

    return marco, entradas
