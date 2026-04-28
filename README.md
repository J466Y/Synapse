# 🌌 Synapse Framework

**Synapse** es un middleware de orquestación y automatización de seguridad (SOAR) diseñado para conectar **TheHive** con el ecosistema de defensa de tu organización. Permite transformar alertas aisladas en flujos de trabajo inteligentes, automatizando la creación de casos, el enriquecimiento de observables y la respuesta activa.

---

## 🚀 Capacidades Principales

### 🔌 Integraciones de Observabilidad (Ingestión)
*   **SIEM**: IBM QRadar (AQL Queries), Elasticsearch (Watcher & Logstash).
*   **EDR/XDR**: **FortiEDR**, **Darktrace** (Breach analysis).
*   **Email**: Microsoft Graph API (O365), EWS (Exchange).
*   **Threat Intelligence**: Lexsi, MISP.

### 🤖 Automatización y Respuesta
*   **Enriquecimiento Automático**: Procesamiento de observables en tiempo real.
*   **Cortex Integration**: Lanzamiento automático de analizadores y responders.
*   **Notificaciones**: Slack y Microsoft Teams con plantillas dinámicas.
*   **Respuesta Activa**: Cierre de ofensas en QRadar y gestión de incidentes en Azure Sentinel.

---

## 🛠 Arquitectura de Webhooks

Synapse expone un endpoint centralizado para recibir eventos de TheHive y otras herramientas:

`POST /webhook/listen`

**Características del Pipeline:**
1.  **Procesamiento Asíncrono**: Los webhooks se gestionan en hilos de fondo para garantizar una respuesta inmediata (`200 OK`) y evitar cuellos de botella.
2.  **Identificación Dinámica**: Clasificación automática del tipo de evento (New Case, New Artifact, Job Success).
3.  **Cola Persistente**: Utiliza un sistema de `EventScheduler` con escrituras atómicas para garantizar que ninguna tarea se pierda tras un reinicio.

---

## 🛡 Seguridad de Grado Industrial

Tras nuestra última auditoría de hardening, Synapse incluye protecciones avanzadas:
*   **Anti-SSRF**: Validación estricta de dominios para peticiones salientes (Azure, Graph API).
*   **Query Sanitization**: Prevención de inyecciones en AQL y Lucene mediante consultas estructuradas y saneamiento centralizado.
*   **Atomic Persistence**: Sistema de guardado de cola de tareas a prueba de fallos y corrupción de datos mediante `os.replace`.
*   **Input Validation**: Validación estricta de payloads JSON, control de tipos y límites de tamaño (DoS protection).
*   **TLS Enforcement**: Verificación configurable de certificados para prevenir ataques Man-in-the-Middle (MiTM).

---

## 📖 Guía Rápida

1.  **Instalación**: `pip3 install -r requirements.txt`
2.  **Configuración**: Ajusta los parámetros en `conf/synapse.conf`.
3.  **Ejecución**: `python3 app.py`

---
## Roadmap

   * Cierre automático de incidentes tras resolución en TheHive -> **Completado**
   * Programador de tareas periódicas robusto -> **Completado**
   * **ToDo**: Implementación de detección avanzada de dominios TLD para enriquecimiento.

---
## Agradecimientos Especiales

Kudos a **ninsmith** por la base original de Synapse.
Kudos a todos los contribuidores de la comunidad de **TheHive** y **Cortex**.

*Desarrollado con foco en la eficiencia operativa y la seguridad proactiva.*