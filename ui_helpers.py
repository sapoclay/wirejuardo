import tkinter as tk
from tkinter import ttk


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
