# Contrato previsto de Proxy Server

- Ejecuta un Tailscale Exit Node de la tailnet Stark, sujeto a la aprobación/políticas de Tailscale.
- Administra una lista blanca de equipos. La lista gráfica NO equivale a ACL de Exit Node: la política efectiva se implementará y probará en una fase posterior.
- El servicio de salud debe comprobar el estado real y no confundirse con autorización.
- No se habilita el reenvío IP, servicios, rutas ni políticas durante esta etapa estructural.
