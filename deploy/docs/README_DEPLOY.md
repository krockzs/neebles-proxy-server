# NEEBLES Proxy Server — entrega de ensayo 008

Paquete de preparación para el **Server dedicado** (`server-20fms4udus`), construido en Ryzen.

El binario `neebles-proxy-server-health` ofrece solo `/health`; **NO** realiza IP forwarding, no anuncia Exit Node, no impone lista blanca sobre tráfico de salida y no está integrado todavía con el lifecycle de Boss.

La unidad systemd incluida es un **borrador para revisión**, no se instala ni habilita automáticamente.

- Directorio futuro del ejecutable: `/opt/neebles-proxy-server/bin/`.
- Política futura: `/opt/neebles-proxy-server/etc/allowlist.json`.
- Unidad futura: `neebles-proxy-server-health.service`.
- Cuenta futura prevista: `server` (verificar usuario y permisos en destino).

La validación del paquete y las dependencias con `ldd` debe realizarse antes de distribuirlo, y hay que integrar CUSTOM V2 / Esbirro y Boss antes de llamar instalable al artefacto.
