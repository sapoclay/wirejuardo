import os
import tkinter as tk
from tkinter import ttk
import webbrowser

from PIL import Image, ImageTk


def crear_menu_superior(raiz):
    """Crea el menú superior con Archivo > Salir y About."""
    barra_menu = tk.Menu(raiz)

    menu_archivo = tk.Menu(barra_menu, tearoff=0)
    menu_archivo.add_command(label="Salir", command=raiz.quit)
    barra_menu.add_cascade(label="Archivo", menu=menu_archivo)

    menu_about = tk.Menu(barra_menu, tearoff=0)
    menu_about.add_command(label="About", command=lambda: mostrar_about(raiz))
    barra_menu.add_cascade(label="About", menu=menu_about)

    menu_ayuda = tk.Menu(barra_menu, tearoff=0)
    menu_ayuda.add_command(label="Guía de campos", command=lambda: mostrar_ayuda(raiz))
    barra_menu.add_cascade(label="Ayuda", menu=menu_ayuda)

    raiz.config(menu=barra_menu)
    return barra_menu


def mostrar_about(raiz):
    """Muestra la ventana About con logo, características y enlace."""
    ventana = tk.Toplevel(raiz)
    ventana.title("About")
    ventana.geometry("420x520")
    ventana.resizable(False, False)

    contenedor = tk.Frame(ventana, padx=12, pady=12)
    contenedor.pack(fill="both", expand=True)

    ruta_logo = os.path.join(os.path.dirname(__file__), "img", "logo.png")
    if os.path.exists(ruta_logo):
        try:
            imagen = Image.open(ruta_logo)
            resampling = getattr(Image, "Resampling", None)
            if resampling is not None:
                imagen.thumbnail((260, 260), resampling.LANCZOS)
            else:
                imagen.thumbnail((260, 260))
            logo = ImageTk.PhotoImage(imagen)
            etiqueta_logo = tk.Label(contenedor, image=logo)
            setattr(ventana, "_logo", logo)
            etiqueta_logo.pack(pady=(0, 12))
        except Exception:
            tk.Label(contenedor, text="(logo no compatible)").pack(pady=(0, 12))
    else:
        tk.Label(contenedor, text="(logo no encontrado)").pack(pady=(0, 12))

    tk.Label(contenedor, text="Características:", anchor="w").pack(fill="x")

    caracteristicas = [
        "• Generación de claves WireGuard",
        "• Creación de configuraciones cliente/servidor",
        "• Instalación automática en Debian/Kali/Ubuntu",
        "• Gestión de wg-quick (activar/desactivar)",
        "• Configuración básica de iptables",
        "• Registro detallado de acciones",
    ]
    texto = tk.Text(contenedor, height=8, width=48, wrap="word", borderwidth=0)
    texto.insert("1.0", "\n".join(caracteristicas))
    texto.configure(state="disabled")
    texto.pack(pady=(6, 12), fill="x")

    def abrir_enlace():
        gtk_path_original = os.environ.pop("GTK_PATH", None)
        try:
            webbrowser.open("https://github.com/sapoclay/wirejuardo")
        finally:
            if gtk_path_original is not None:
                os.environ["GTK_PATH"] = gtk_path_original

    tk.Button(contenedor, text="Abrir repositorio", command=abrir_enlace).pack()


def _crear_pestana_ayuda(cuaderno, titulo, pasos):
    marco = ttk.Frame(cuaderno, padding=12)
    cuaderno.add(marco, text=titulo)

    etiqueta = ttk.Label(
        marco,
        text="Completa los campos en este orden:",
        anchor="w",
    )
    etiqueta.pack(fill="x", pady=(0, 8))

    texto = tk.Text(marco, height=18, width=70, wrap="word", borderwidth=0)
    texto.insert("1.0", "\n".join(pasos))
    texto.configure(state="disabled")
    texto.pack(fill="both", expand=True)

    return marco


def mostrar_ayuda(raiz):
    """Muestra una guía paso a paso para completar los campos."""
    ventana = tk.Toplevel(raiz)
    ventana.title("Guía de campos")
    ventana.geometry("560x460")
    ventana.resizable(False, False)

    contenedor = ttk.Frame(ventana, padding=10)
    contenedor.pack(fill="both", expand=True)

    cuaderno = ttk.Notebook(contenedor)
    cuaderno.pack(fill="both", expand=True)

    pasos_servidor = [
        "1) Nombre de interfaz: el nombre de la interfaz WireGuard del servidor (ej: wg0).",
        "2) Address: IP del servidor en el túnel (ej: 10.0.0.1/24).",
        "3) ListenPort: puerto UDP del servidor (ej: 51820).",
        "4) PrivateKey: clave privada del servidor (puede generarse con Generar claves).",
        "5) PublicKey del cliente: clave pública del cliente (para crear el peer).",
        "6) AllowedIPs del cliente: IP del cliente (ej: 10.0.0.2/32).",
        "7) Red interna (NAT): red del túnel (ej: 10.0.0.0/24).",
        "8) Interfaz de salida: interfaz con salida a Internet (ej: eth0).",
        "9) Interfaz WireGuard: interfaz del túnel (ej: wg0).",
    ]

    pasos_cliente = [
        "1) Nombre de interfaz: el nombre de la interfaz WireGuard del cliente (ej: wg0).",
        "2) Address: IP del cliente en el túnel (ej: 10.0.0.2/32).",
        "3) PrivateKey: clave privada del cliente (puede generarse con Generar claves).",
        "4) DNS: servidor DNS para el cliente (ej: 1.1.1.1).",
        "5) PublicKey del servidor: clave pública del servidor.",
        "6) Endpoint: IP/Dominio y puerto del servidor (ej: vpn.example.com:51820).",
        "7) AllowedIPs: rutas permitidas por el túnel (ej: 0.0.0.0/0, ::/0).",
        "8) PersistentKeepalive: mantener NAT abierto (opcional, ej: 25).",
    ]

    _crear_pestana_ayuda(cuaderno, "Servidor", pasos_servidor)
    _crear_pestana_ayuda(cuaderno, "Cliente", pasos_cliente)
