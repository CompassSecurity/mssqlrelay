from importlib.metadata import version as _get_version, PackageNotFoundError
from impacket import __path__

try:
    version = _get_version("mssqlrelay")
except PackageNotFoundError:
    version = "?"
    print(
        "Cannot determine MSSQLRelay version. "
        'If running from source you should at least run "python setup.py egg_info"'
    )
BANNER = "MSSQLRelay v{} - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)\n".format(version)