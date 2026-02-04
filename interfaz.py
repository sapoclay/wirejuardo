import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from menu_superior import crear_menu_superior
from pestanas_cliente import crear_pestana_cliente
from pestanas_servidor import crear_pestana_servidor
from ui_helpers import Tooltip, crear_registro
from wireguard_utils import (
    activar_interfaz,
    comprobar_wireguard,
    desactivar_interfaz,
    obtener_reglas_iptables,
    instalar_wireguard,
    wg_disponible,
)

TITULO_APP = "Configurador de WireGuard"




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

    def _mostrar_texto_scroll(titulo, contenido):
        ventana = tk.Toplevel(raiz)
        ventana.title(titulo)
        ventana.geometry("760x520")
        ventana.resizable(True, True)

        contenedor = ttk.Frame(ventana, padding=8)
        contenedor.pack(fill="both", expand=True)

        barra = ttk.Scrollbar(contenedor, orient="vertical")
        barra.pack(side="right", fill="y")

        texto = tk.Text(contenedor, wrap="word", yscrollcommand=barra.set)
        texto.insert("1.0", contenido)
        texto.configure(state="disabled")
        texto.pack(side="left", fill="both", expand=True)

        barra.config(command=texto.yview)

    def al_ver_iptables():
        ok, mensaje, reglas = obtener_reglas_iptables(registrar_log)
        if ok and reglas:
            _mostrar_texto_scroll("iptables", reglas)
        elif ok:
            messagebox.showinfo("iptables", "No hay reglas para mostrar.")
        else:
            messagebox.showwarning("iptables", mensaje)

    cuaderno = ttk.Notebook(raiz)
    cuaderno.pack(fill="both", expand=True, padx=8, pady=8)

    marco_servidor, entradas_servidor = crear_pestana_servidor(cuaderno, registrar_log)
    marco_cliente, entradas_cliente = crear_pestana_cliente(cuaderno, registrar_log)

    def obtener_valor_entrada(entradas, clave):
        entrada = entradas.get(clave)
        return entrada.get().strip() if entrada else ""

    def al_comprobar():
        indice_actual = cuaderno.index(cuaderno.select())
        texto_pestana = cuaderno.tab(indice_actual, "text")
        rol = "servidor" if texto_pestana == "Servidor" else "cliente"

        if rol == "servidor":
            interfaz = (
                obtener_valor_entrada(entradas_servidor, "nombre_interfaz")
                or obtener_valor_entrada(entradas_servidor, "interfaz_wg")
            )
        else:
            interfaz = obtener_valor_entrada(entradas_cliente, "nombre_interfaz")

        if not interfaz:
            mensaje = (
                "No se pudo determinar la interfaz desde el formulario. "
                "Completa el campo correspondiente antes de comprobar."
            )
            registrar_log(mensaje)
            messagebox.showwarning("Comprobación", mensaje)
            return

        ip = simpledialog.askstring(
            "Comprobar",
            "IP del peer para ping (opcional):",
            parent=raiz,
        )
        ok, mensaje = comprobar_wireguard(ip or "", registrar_log, interfaz, rol)
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
    btn_ipt_view = ttk.Button(acciones_sistema, text="Ver iptables", command=al_ver_iptables)
    btn_ipt_view.pack(side="left", padx=4)
    Tooltip(btn_ipt_view, "Muestra las reglas actuales de iptables.")
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
