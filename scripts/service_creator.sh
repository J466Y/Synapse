#!/bin/bash

SERVICE_NAME="synapse.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

read -r -d '' SERVICE_CONTENT << 'EOF'
[Unit]
Description=Synapse TheHive / Cortex feeder
After=network.target thehive.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Synapse
ExecStart=/opt/Synapse/venv/bin/python3.9 app.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Comprobación de permisos
if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root"
    exit 1
fi

# Si el servicio ya existe, no lo sobrescribe
if [ -f "$SERVICE_PATH" ]; then
    echo "El servicio ya existe en $SERVICE_PATH"
else
    echo "$SERVICE_CONTENT" > "$SERVICE_PATH"
    echo "Servicio creado en $SERVICE_PATH"
fi

# Recargar systemd
systemctl daemon-reexec
systemctl daemon-reload

# Habilitar servicio al arranque
systemctl enable "$SERVICE_NAME"

# Arrancar servicio
systemctl restart "$SERVICE_NAME"

# Estado final
systemctl status "$SERVICE_NAME" --no-pager