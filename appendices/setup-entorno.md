# Configuración del Entorno de Trabajo

Este apéndice explica cómo preparar el entorno Python necesario para ejecutar los notebooks del curso en tu máquina local.

Los notebooks de este curso trabajan con archivos JSONL que pueden superar los 2 GB. Por este motivo, **no es viable ejecutarlos en Google Colab** — el entorno de ejecución debe ser local.

---

## Prerrequisitos

- **Python 3.10 o superior** instalado en tu sistema.
- **Git** para clonar el repositorio.
- El repositorio ya clonado en tu máquina.

---

## 1. Clonar el repositorio

```bash
git clone https://github.com/ollerenac/curso2026.git
cd curso2026
```

---

## 2. Crear el entorno virtual

Un entorno virtual aísla las dependencias del curso del resto de tu sistema Python, evitando conflictos de versiones.

**Linux / macOS:**

```bash
python3 -m venv .venv
```

**Windows (cmd o PowerShell):**

```cmd
python -m venv .venv
```

---

## 3. Activar el entorno virtual

Debes activar el entorno cada vez que abras una nueva terminal para trabajar con el curso.

**Linux / macOS:**

```bash
source .venv/bin/activate
```

**Windows (cmd):**

```cmd
.venv\Scripts\activate.bat
```

**Windows (PowerShell):**

```powershell
.venv\Scripts\Activate.ps1
```

Sabrás que el entorno está activo cuando veas `(.venv)` al inicio del prompt de tu terminal.

---

## 4. Instalar las dependencias

Con el entorno activado, instala todos los paquetes necesarios:

```bash
pip install -r requirements.txt
```

Este comando instala automáticamente las librerías utilizadas en los notebooks: `pandas`, `numpy`, `matplotlib`, `seaborn`, `scipy`, `elasticsearch`, entre otras.

---

## 5. Registrar el kernel en Jupyter

Para que Jupyter detecte el entorno virtual como un kernel disponible:

```bash
python -m ipykernel install --user --name curso2026 --display-name "Python (curso2026)"
```

---

## 6. Abrir Jupyter

```bash
jupyter notebook
```

Navega hasta la carpeta de la sesión correspondiente y abre el notebook. Asegúrate de seleccionar el kernel **"Python (curso2026)"** en el menú `Kernel → Change kernel`.

---

## Verificar la instalación

Ejecuta esta celda en cualquier notebook para confirmar que el entorno está correctamente configurado:

```python
import pandas, numpy, matplotlib, seaborn, scipy, elasticsearch
print(f"pandas {pandas.__version__} — OK")
print(f"numpy {numpy.__version__} — OK")
print(f"elasticsearch {elasticsearch.__version__} — OK")
print("Entorno configurado correctamente.")
```

---

## Desactivar el entorno

Cuando termines de trabajar:

```bash
deactivate
```
