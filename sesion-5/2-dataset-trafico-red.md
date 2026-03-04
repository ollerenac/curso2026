# Dataset de Tráfico de Red

**Duración**: 90 minutos

## Script del Pipeline

Esta sección cubre el siguiente script del pipeline de procesamiento:

| Script | Archivo | Tamaño |
|--------|---------|--------|
| **Script 10** | `10_create_labeled_netflow_dataset.py` | 103.5 KB |

### Script 10: Generador de Dataset NetFlow Etiquetado

Genera una matriz de verificación (`verification_matrix_run-XX.csv`, 42 columnas) correlacionando los eventos semilla del etiquetado de Sysmon con datos NetFlow. Implementa configuración interactiva de IPs (IP del atacante, redes en scope, modo de scope) y aplica lógica refinada de causalidad/atribución.

- **Entrada**: Eventos semilla etiquetados de Sysmon + `netflow-run-XX.csv`
- **Salida**: `verification_matrix_run-XX.csv` — matriz de 42 columnas con correlaciones Sysmon-NetFlow
- **Configuración interactiva**: IP del atacante, redes in-scope, modo de scope (restricted/unrestricted)
- **Lógica de correlación**: Matching computer-hostname, ventana temporal configurable (±10s por defecto), filtrado de tráfico ICMP, filtrado TCP de Domain Controller
- **Modos de scope**: Restricted (whitelist de IPs) o Unrestricted (blacklist de IPs)

## Contenido

*Por desarrollar.*
