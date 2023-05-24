from setuptools import setup

with open("README.md") as f:
    readme = f.read()

setup(
    name="mssqlrelay",
    version="1.0",
    license="MIT",
    author="sploutchy",
    url="https://github.com/compasssecurity/mssqlrelay",
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=[
        "asn1crypto",
        "cryptography>=37.0",
        "impacket>0.10.0",
        "ldap3",
        "pyasn1==0.4.8",
        "dnspython",
        "dsinternals",
        "pyopenssl>=22.0.0",
        "requests",
        "requests_ntlm",
        'winacl; platform_system=="Windows"',
        'wmi; platform_system=="Windows"',
    ],
    packages=[
        "mssqlrelay",
        "mssqlrelay.commands",
        "mssqlrelay.commands.parsers",
        "mssqlrelay.lib",
    ],
    entry_points={
        "console_scripts": ["mssqlrelay=mssqlrelay.entry:main"],
    },
    description="Microsoft SQL Relay audit and abuse tool",
)
