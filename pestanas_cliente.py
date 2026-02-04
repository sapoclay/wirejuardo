import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from configuraciones import (
    construir_config_cliente,
    crear_wg0_conf,
    guardar_configuracion,
    validar_campos,
)
from ui_helpers import Tooltip, agregar_entrada_etiquetada
from wireguard_utils import generar_par_claves


def crear_pestana_cliente(cuaderno, registrar_log):
    """Pestaña con formularios para configurar el cliente."""
    marco = ttk.Frame(cuaderno, padding=10)
    cuaderno.add(marco, text="Cliente")

    entradas = {}
    entradas["nombre_interfaz"] = agregar_entrada_etiquetada(marco, 0, "Nombre de interfaz (ej: wg0)")
    Tooltip(entradas["nombre_interfaz"], "Nombre de la interfaz WireGuard del cliente.")
    entradas["direccion"] = agregar_entrada_etiquetada(marco, 1, "Address (ej: 10.0.0.2/32)")
    Tooltip(entradas["direccion"], "IP y máscara del cliente.")
    entradas["clave_privada"] = agregar_entrada_etiquetada(marco, 2, "PrivateKey")
    Tooltip(entradas["clave_privada"], "Clave privada del cliente.")
    entradas["dns"] = agregar_entrada_etiquetada(marco, 3, "DNS (ej: 1.1.1.1)")
    Tooltip(entradas["dns"], "DNS que usará el cliente.")
    entradas["clave_publica_peer"] = agregar_entrada_etiquetada(marco, 4, "PublicKey del servidor")
    Tooltip(entradas["clave_publica_peer"], "Clave pública del servidor.")
    entradas["endpoint"] = agregar_entrada_etiquetada(marco, 5, "Endpoint (ej: vpn.example.com:51820)")
    Tooltip(entradas["endpoint"], "IP/Dominio y puerto del servidor.")
    entradas["ips_permitidas"] = agregar_entrada_etiquetada(marco, 6, "AllowedIPs (ej: 0.0.0.0/0, ::/0)")
    Tooltip(entradas["ips_permitidas"], "Rutas permitidas a través del túnel.")
    entradas["keepalive"] = agregar_entrada_etiquetada(marco, 7, "PersistentKeepalive (opcional, ej: 25)")
    Tooltip(entradas["keepalive"], "Mantiene el NAT abierto.")

    def al_generar_claves():
        registrar_log("Iniciando generación de claves para cliente...")
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
        nombre_base = "wg0"
        if not directorio:
            registrar_log("Guardado de claves cancelado por el usuario.")
            registrar_log(
                "No se guardaron archivos: "
                f"{nombre_base}.privkey, {nombre_base}.pubkey"
            )
            messagebox.showinfo(
                "Clave pública",
                "Clave pública copiada al portapapeles:\n\n" + clave_publica,
            )
            return
        ruta_privada = os.path.join(directorio, f"{nombre_base}.privkey")
        ruta_publica = os.path.join(directorio, f"{nombre_base}.pubkey")
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

    def al_previsualizar():
        registrar_log("Generando previsualización de la configuración del cliente...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        contenido = construir_config_cliente(valores)
        vista_previa.delete("1.0", tk.END)
        vista_previa.insert(tk.END, contenido)

    def al_guardar():
        registrar_log("Guardando configuración del cliente...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        contenido = construir_config_cliente(valores)
        ruta, error = guardar_configuracion(contenido, "wg0.conf", registrar_log)
        if ruta:
            messagebox.showinfo("Guardado", f"Configuración guardada en:\n{ruta}")
        elif error:
            messagebox.showerror("Guardado", f"No se pudo guardar la configuración:\n{error}")

    def al_crear_wg0():
        registrar_log("Creando wg0.conf para cliente...")
        valores = {k: e.get().strip() for k, e in entradas.items()}
        faltantes = validar_campos(
            valores,
            ["direccion", "clave_privada", "clave_publica_peer", "endpoint", "ips_permitidas"],
        )
        if faltantes:
            mensaje = "Faltan campos: " + ", ".join(faltantes)
            registrar_log(mensaje)
            messagebox.showerror("Datos incompletos", mensaje)
            return
        contenido = construir_config_cliente(valores)
        ruta, error = crear_wg0_conf(contenido, registrar_log)
        if ruta:
            messagebox.showinfo("wg0.conf", f"Archivo creado en:\n{ruta}")
        elif error:
            messagebox.showerror("wg0.conf", f"No se pudo crear el archivo:\n{error}")

    acciones = ttk.Frame(marco)
    acciones.grid(row=8, column=0, columnspan=2, sticky="w", pady=(4, 8))
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

    vista_previa = tk.Text(marco, height=12, width=72)
    vista_previa.grid(row=9, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)

    marco.columnconfigure(1, weight=1)
    marco.rowconfigure(9, weight=1)

    return marco, entradas
