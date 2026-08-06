from . import nikto, nmap, sslscan, subfinder, whatweb


INTEGRATIONS = {
    "subfinder": subfinder,
    "nmap": nmap,
    "whatweb": whatweb,
    "nikto": nikto,
    "sslscan": sslscan,
}
