#!/bin/bash

CRON_JOB="*/20 * * * * /usr/bin/python3 /home/operador/scripts/synapse_syn_cron_launcher.py >> /var/log/synapse_sync.log 2>&1"
TMP_FILE=$(mktemp)

# Dump del crontab actual
crontab -l 2>/dev/null > "$TMP_FILE"

# Comprobación de duplicado
if grep -Fq "$CRON_JOB" "$TMP_FILE"; then
    echo "La tarea ya existe en el crontab de root. No se realizan cambios."
else
    echo "$CRON_JOB" >> "$TMP_FILE"

    # Validación básica antes de aplicar
    crontab "$TMP_FILE" && echo "Tarea añadida correctamente." || echo "Error al aplicar el crontab"
fi

rm -f "$TMP_FILE"