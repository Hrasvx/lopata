from . import (attack_surface, clickjacking, cookies, cors, crawler, csrf,
               exposure, fingerprint, headers, misconfig, open_redirect, sqli,
               xss)


# name -> (module, requires the crawler to have run first)
# Order is execution order: discovery and fingerprinting first, so the checks
# that depend on knowing the stack and the URL inventory can use them.
MODULES = {
    "crawler": (crawler, False),
    "fingerprint": (fingerprint, False),
    "attack_surface": (attack_surface, False),
    "headers": (headers, False),
    "cookies": (cookies, False),
    "clickjacking": (clickjacking, False),
    "cors": (cors, True),
    "exposure": (exposure, False),
    "misconfig": (misconfig, True),
    "redirect": (open_redirect, True),
    "csrf": (csrf, True),
    "xss": (xss, True),
    "sqli": (sqli, True),
}
