import argparse
import random
import struct

from impacket.tds import MSSQL, TDS_PRELOGIN, TDS_ENCRYPT_NOT_SUP, TDS_PRE_LOGIN

from mssqlrelay.lib.logger import logging
from mssqlrelay.lib.target import Target

class Check:
    def __init__(
            self,
            target: Target,
            connection: MSSQL = None):
        self.target = target
        self._connection = connection

    @property
    def connection(self) -> MSSQL:
        if self._connection is not None:
            return self._connection

        self._connection = MSSQL(self.target.target_ip, self.target.mssql_port)
        self._connection.connect()

        return self._connection

    def disconnect(self):
        if self._connection:
            self._connection.disconnect()

    def check(self):
        try:
            prelogin = TDS_PRELOGIN()
            prelogin['Version'] = b"\x08\x00\x01\x55\x00\x00"
            prelogin['Encryption'] = TDS_ENCRYPT_NOT_SUP
            prelogin['ThreadID'] = struct.pack('<L', random.randint(0, 65535))
            prelogin['Instance'] = b'MSSQLServer\x00'

            self.connection.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0)
            tds = self.connection.recvTDS()
            response = TDS_PRELOGIN(tds['Data'])

            version = "%i.%i.%i" % struct.unpack_from('>bbH', response['Version'])
            encryption = ("no " if response['Encryption'] == TDS_ENCRYPT_NOT_SUP else "") + "encryption"
            logging.info("%s (%s): version %s, %s" % (self.target.remote_name, self.target.target_ip, version, encryption))
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error(str(e))


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)
    del options.target

    check = Check(target)
    check.check()
