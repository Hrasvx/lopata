from . import (clickjacking, cookies, cors, crawler, csrf, exposure, headers,
               misconfig, open_redirect, sqli, xss)


MODULES = {
    "crawler": (crawler, False),
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
