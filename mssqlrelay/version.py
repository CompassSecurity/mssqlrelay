import pkg_resources
from impacket import __path__

try:
    version = pkg_resources.get_distribution("mssqlrelay").version
except pkg_resources.DistributionNotFound:
    version = "?"
    print(
        "Cannot determine MSSQLRelay version. "
        'If running from source you should at least run "python setup.py egg_info"'
    )
BANNER = "MSSQLRelay v{} - by Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)\n".format(version)