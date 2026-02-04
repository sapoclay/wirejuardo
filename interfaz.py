import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from configuraciones import (
    construir_config_cliente,
    construir_config_servidor,
    crear_wg0_conf,
    guardar_configuracion,
    validar_campos,
)
from menu_superior import crear_menu_superior
from wireguard_utils import (
    activar_interfaz,
    comprobar_wireguard,
    desactivar_interfaz,
    generar_par_claves,
    habilitar_ip_forwarding,
    iptables_disponible,
    aplicar_reglas_iptables,
    eliminar_reglas_iptables,
    instalar_wireguard,
    wg_disponible,
)

TITULO_APP = "Configurador de WireGuard"


class Tooltip:
    """Tooltip simple para widgets de Tkinter."""

    def __init__(self, widget, texto):
        self.widget = widget
        self.texto = texto
        self.ventana = None
        widget.bind("<Enter>", self.mostrar)
        widget.bind("<Leave>", self.ocultar)

    def mostrar(self, _evento=None):
        if self.ventana or not self.texto:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.ventana = tk.Toplevel(self.widget)
        self.ventana.wm_overrideredirect(True)
        self.ventana.wm_geometry(f"+{x}+{y}")
        etiqueta = tk.Label(
            self.ventana,
            text=self.texto,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=3,
        )
        etiqueta.pack()

    def ocultar(self, _evento=None):
        if self.ventana:
            self.ventana.destroy()
            self.ventana = None


def crear_registro(raiz):
    """Crea el panel de registro de acciones."""
    marco_log = ttk.Frame(raiz)
    marco_log.pack(fill="both", expand=False, padx=8, pady=(8, 0))
    ttk.Label(marco_log, text="Registro de acciones").pack(anchor="w")

    texto_log = tk.Text(marco_log, height=8, width=90, state="disabled")
    texto_log.pack(fill="both", expand=True, pady=(4, 8))

    def registrar_log(mensaje):
        texto_log.configure(state="normal")
        texto_log.insert(tk.END, f"{mensaje}\n")
        texto_log.see(tk.END)
        texto_log.configure(state="disabled")

    def limpiar_log():
        texto_log.configure(state="normal")
        texto_log.delete("1.0", tk.END)
        texto_log.configure(state="disabled")

    return registrar_log, limpiar_log


def agregar_entrada_etiquetada(padre, fila, etiqueta, ancho=48):
    """Crea una etiqueta con entrada asociada y la devuelve."""
    ttk.Label(padre, text=etiqueta).grid(row=fila, column=0, sticky="w", padx=6, pady=4)
    entrada = ttk.Entry(padre, width=ancho)
    entrada.grid(row=fila, column=1, sticky="ew", padx=6, pady=4)
    return entrada


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
        ruta = guardar_configuracion(contenido, nombre, registrar_log)
        if ruta:
            messagebox.showinfo("Guardado", f"Configuración guardada en:\n{ruta}")

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
        ruta = crear_wg0_conf(contenido, registrar_log)
        if ruta:
            messagebox.showinfo("wg0.conf", f"Archivo creado en:\n{ruta}")

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

    return marco


def crear_pestana_cliente(cuaderno, registrar_log):
    """Pestaña con formularios para configurar el cliente."""
    marco = ttk.Frame(cuaderno, padding=10)
    cuaderno.add(marco, text="Cliente")

    entradas = {}
    entradas["direccion"] = agregar_entrada_etiquetada(marco, 0, "Address (ej: 10.0.0.2/32)")
    Tooltip(entradas["direccion"], "IP y máscara del cliente.")
    entradas["clave_privada"] = agregar_entrada_etiquetada(marco, 1, "PrivateKey")
    Tooltip(entradas["clave_privada"], "Clave privada del cliente.")
    entradas["dns"] = agregar_entrada_etiquetada(marco, 2, "DNS (ej: 1.1.1.1)")
    Tooltip(entradas["dns"], "DNS que usará el cliente.")
    entradas["clave_publica_peer"] = agregar_entrada_etiquetada(marco, 3, "PublicKey del servidor")
    Tooltip(entradas["clave_publica_peer"], "Clave pública del servidor.")
    entradas["endpoint"] = agregar_entrada_etiquetada(marco, 4, "Endpoint (ej: vpn.example.com:51820)")
    Tooltip(entradas["endpoint"], "IP/Dominio y puerto del servidor.")
    entradas["ips_permitidas"] = agregar_entrada_etiquetada(marco, 5, "AllowedIPs (ej: 0.0.0.0/0, ::/0)")
    Tooltip(entradas["ips_permitidas"], "Rutas permitidas a través del túnel.")
    entradas["keepalive"] = agregar_entrada_etiquetada(marco, 6, "PersistentKeepalive (opcional, ej: 25)")
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
        ruta = guardar_configuracion(contenido, "wg0.conf", registrar_log)
        if ruta:
            messagebox.showinfo("Guardado", f"Configuración guardada en:\n{ruta}")

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
        ruta = crear_wg0_conf(contenido, registrar_log)
        if ruta:
            messagebox.showinfo("wg0.conf", f"Archivo creado en:\n{ruta}")

    acciones = ttk.Frame(marco)
    acciones.grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 8))
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
    vista_previa.grid(row=8, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)

    marco.columnconfigure(1, weight=1)
    marco.rowconfigure(8, weight=1)

    return marco


def crear_app():
    """Construye la interfaz principal de la aplicación."""
    raiz = tk.Tk()
    raiz.title(TITULO_APP)
    raiz.geometry("820x700")

    crear_menu_superior(raiz)

    registrar_log, limpiar_log = crear_registro(raiz)

    if not wg_disponible():
        mensaje = (
            "WireGuard no está instalado. Para instalar en Debian/Kali usa:\n"
            "sudo apt-get update && sudo apt-get install -y wireguard"
        )
        registrar_log(mensaje)
        messagebox.showwarning("WireGuard no instalado", mensaje)

    def seleccionar_configuracion():
        registrar_log("Seleccionando archivo de configuración...")
        ruta = filedialog.askopenfilename(
            title="Seleccionar configuración",
            filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
        )
        if not ruta:
            registrar_log("Selección cancelada por el usuario.")
            return None
        registrar_log(f"Configuración seleccionada: {ruta}")
        return ruta

    def al_instalar():
        ok, mensaje = instalar_wireguard(registrar_log)
        if ok:
            messagebox.showinfo("Instalación", mensaje)
        else:
            messagebox.showwarning("Instalación", mensaje)

    def al_activar():
        ruta = seleccionar_configuracion()
        if not ruta:
            return
        ok, mensaje = activar_interfaz(ruta, registrar_log)
        if ok:
            messagebox.showinfo("wg-quick", mensaje)
        else:
            messagebox.showerror("wg-quick", mensaje)

    def al_desactivar():
        ruta = seleccionar_configuracion()
        if not ruta:
            return
        ok, mensaje = desactivar_interfaz(ruta, registrar_log)
        if ok:
            messagebox.showinfo("wg-quick", mensaje)
        else:
            messagebox.showerror("wg-quick", mensaje)

    cuaderno = ttk.Notebook(raiz)
    cuaderno.pack(fill="both", expand=True, padx=8, pady=8)

    crear_pestana_servidor(cuaderno, registrar_log)
    crear_pestana_cliente(cuaderno, registrar_log)

    def al_comprobar():
        ip = simpledialog.askstring("Comprobar", "IP del peer para ping (opcional):", parent=raiz)
        ok, mensaje = comprobar_wireguard(ip or "", registrar_log)
        if ok:
            messagebox.showinfo("Comprobación", mensaje)
        else:
            messagebox.showwarning("Comprobación", mensaje)

    acciones_sistema = ttk.Frame(raiz)
    acciones_sistema.pack(fill="x", padx=10, pady=(0, 6))
    btn_inst = ttk.Button(acciones_sistema, text="Instalar WireGuard", command=al_instalar)
    btn_inst.pack(
        side="left", padx=4
    )
    Tooltip(btn_inst, "Instala WireGuard en Debian/Kali/Ubuntu.")
    btn_up = ttk.Button(acciones_sistema, text="Activar wg-quick", command=al_activar)
    btn_up.pack(
        side="left", padx=4
    )
    Tooltip(btn_up, "Levanta la interfaz usando wg-quick.")
    btn_down = ttk.Button(acciones_sistema, text="Desactivar wg-quick", command=al_desactivar)
    btn_down.pack(
        side="left", padx=4
    )
    Tooltip(btn_down, "Baja la interfaz usando wg-quick.")
    btn_chk = ttk.Button(acciones_sistema, text="Comprobar WireGuard", command=al_comprobar)
    btn_chk.pack(side="left", padx=4)
    Tooltip(btn_chk, "Ejecuta wg show, ip a, ip route y un ping opcional.")
    btn_clear = ttk.Button(acciones_sistema, text="Limpiar registro", command=limpiar_log)
    btn_clear.pack(
        side="left", padx=4
    )
    Tooltip(btn_clear, "Limpia el registro de acciones.")

    etiqueta_info = ttk.Label(
        raiz,
        text=(
            "Este asistente genera archivos .conf para WireGuard. "
            "Para activar, usa wg-quick (requiere permisos de administrador)."
        ),
        wraplength=760,
        justify="left",
    )
    etiqueta_info.pack(padx=10, pady=(0, 10), anchor="w")

    return raiz


def principal():
    """Punto de entrada de la aplicación."""
    app = crear_app()
    app.mainloop()
