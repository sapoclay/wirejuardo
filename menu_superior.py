import os
import tkinter as tk
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
            imagen.thumbnail((260, 260), Image.LANCZOS)
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
