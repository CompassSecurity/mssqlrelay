import argparse
import random
import struct

from impacket.tds import MSSQL, TDS_PRELOGIN, TDS_ENCRYPT_NOT_SUP, TDS_PRE_LOGIN, TDS_ERROR_TOKEN

from mssqlrelay.lib.logger import logging
from mssqlrelay.lib.target import Target

class MSSQL_VERSION:
    # from https://sqlserverbuilds.blogspot.com/
    VERSION_NAME = ("Microsoft SQL Server", {
        # Out of support
        6 : ("6", {
            0 : (".0", {
                121 : "RTM (no SP)",
                124 : "(SP1)",
                139 : "(SP2)",
                151 : "(SP3)",
            }),
            50 : (".5", {
                201 : "RTM (no SP)",
                213 : "(SP1)",
                240 : "(SP2)",
                258 : "(SP3)",
                281 : "(SP4)",
                416 : "(SP5)",
            }),
        }),
        7 : ("7", {
            0 : ("", {
                623 : "RTM (no SP)",
                699 : "(SP1)",
                842 : "(SP2)",
                961 : "(SP3)",
                1063 : "(SP4)",
            }),
        }),
        8 : ("2000", {
            0 : ("", {
                194 : "RTM (no SP)",
                384 : "(SP1)",
                532 : "(SP2)",
                760 : "(SP3)",
                2039 : "(SP4)",
            }),
        }),
        9 : ("2005", {
            0 : ("", {
                1399 : "RTM (no SP)",
                2047 : "(SP1)",
                3042 : "(SP2)",
                4035 : "(SP3)",
                5000 : "(SP4)",
            }),
        }),
        10 : ("2008", {
            0 : ("", {
                1600 : "RTM (no SP)",
                2531 : "(SP1)",
                4000 : "(SP2)",
                5500 : "(SP3)",
                6000 : "(SP4)",
            }),
            50 : (" R2", {
                1600 : "RTM (no SP)",
                2500 : "(SP1)",
                4000 : "(SP2)",
                6000 : "(SP3)",
            }),
        }),
        11 : ("2012", {
            0 : ("", {
                2100 : "RTM (no SP)",
                3000 : "(SP1)",
                5058 : "(SP2)",
                6020 : "(SP3)",
                7001 : "(SP4)",
            }),
        }),
        # Supported
        12 : ("2014", {
            0 : ("", {
                2000 : "RTM (no SP)",
                4100 : "(SP1)",
                5000 : "(SP2)",
                6024 : "(SP3)",
            }),
        }),
        13 : ("2016", {
            0 : ("", {
                1601 : "RTM (no SP)",
                4001 : "(SP1)",
                5026 : "(SP2)",
                6300 : "(SP3)",
            }),
        }),
        14 : ("2017", {
            0 : ("", {
                1000 : "RTM",
                3006 : "(CU1)",
                3008 : "(CU2)",
                3015 : "(CU3)",
                3022 : "(CU4)",
                3023 : "(CU5)",
                3025 : "(CU6)",
                3026 : "(CU7)",
                3029 : "(CU8)",
                3030 : "(CU9)",
                3037 : "(CU10)",
                3038 : "(CU11)",
                3045 : "(CU12)",
                3048 : "(CU13)",
                3076 : "(CU14)",
                3162 : "(CU15)",
                3223 : "(CU16)",
                3228 : "(CU17)",
                3257 : "(CU18)",
                3281 : "(CU19)",
                3294 : "(CU20)",
                3335 : "(CU21)",
                3356 : "(CU22)",
                3381 : "(CU23)",
                3391 : "(CU24)",
                3401 : "(CU25)",
                3411 : "(CU26)",
                3421 : "(CU27)",
                3430 : "(CU28)",
                3436 : "(CU29)",
                3451 : "(CU30)",
                3456 : "(CU31)",
            }),
        }),
        15 : ("2019", {
            0 : ("", {
                2000 : "RTM",
                4003 : "(CU1)",
                4013 : "(CU2)",
                4023 : "(CU3)",
                4033 : "(CU4)",
                4043 : "(CU5)",
                4053 : "(CU6)",
                4063 : "(CU7)",
                4073 : "(CU8)",
                4102 : "(CU9)",
                4123 : "(CU10)",
                4138 : "(CU11)",
                4153 : "(CU12)",
                4178 : "(CU13)",
                4188 : "(CU14)",
                4198 : "(CU15)",
                4223 : "(CU16)",
                4249 : "(CU17)",
                4261 : "(CU18)",
                4298 : "(CU19)",
                4312 : "(CU20)",
            }),
        }),
        16 : ("2022", {
            0 : ("", {
                1000 : "RTM",
                4003 : "(CU1)",
                4015 : "(CU2)",
                4025 : "(CU3)",
                4035 : "(CU4)",
            }),
        }),
    })

    def __init__(self, version):
        self.major, self.minor, self.build = struct.unpack_from('>bbH', version)

    @property
    def version_number(self):
        return "%i.%i.%i" % (self.major, self.minor, self.build)

    @property
    def version_name(self):
        try:
            string = MSSQL_VERSION.VERSION_NAME[0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][0]
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][1][self.build]
        except KeyError:
            string += "(unknown)"
        finally:
            return string

    def __repr__(self):
        return "%s (%s)" % (self.version_name, self.version_number)

class Check:
    WELL_KNOWN_PRIVILEGES = ("xp_dirtree", "xp_fileexist", "xp_cmdshell")

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
        self._connection = None

    def check(self):
        self.checkEncryption()
        if len(self.target.username) > 0:
            logged_in = self.checkConnection()
            if logged_in:
                self.checkPrivileges()

    # TODO
    def getInstances(self):
        self.connection.getInstances()

    def checkPrivileges(self):
        # From https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1#L10560
        QUERY = "SELECT rp.name as [PrincipalName], " \
                "rp.type_desc as [PrincipalType], " \
                "pm.class_desc as [PermissionType], " \
                "pm.permission_name as [PermissionName], " \
                "pm.state_desc as [StateDescription], " \
                "ObjectType = CASE WHEN obj.type_desc IS NULL OR obj.type_desc = 'SYSTEM_TABLE' THEN pm.class_desc ELSE obj.type_desc END, " \
                "[ObjectName] = Isnull(ss.name, Object_name(pm.major_id)) FROM sys.database_principals rp " \
                "INNER JOIN sys.database_permissions pm ON pm.grantee_principal_id = rp.principal_id " \
                "LEFT JOIN sys.schemas ss ON pm.major_id = ss.schema_id " \
                "LEFT JOIN sys.objects obj ON pm.[major_id] = obj.[object_id] " \
                "WHERE pm.permission_name like 'EXECUTE' " \
                "AND (rp.name like '%s' OR rp.name like 'public') " \
                "AND pm.state_desc like 'GRANT'" \
                "" % self.db_user
        try:
            rows = self.connection.RunSQLQuery(self.connection.currentDB, QUERY)
            privileges = []
            for row in rows:
                if row['ObjectName'] in Check.WELL_KNOWN_PRIVILEGES:
                    privileges.append(row['ObjectName'])

            if len(privileges) > 0:
                logging.info("  -  Privileges: %s" % privileges)
            else:
                logging.info("  -  Privileges: None")

        except Exception:
            logging.error("An error occured.")
            raise

    def checkConnection(self):
        try:
            success = False
            if self.target.do_kerberos:
                success = self.connection.kerberos_login(self.target.mssql_db, self.target.username, self.target.password, self.target.domain, hashes=self.target.hashes, aesKey=self.target.aes)
            else:
                success = self.connection.login(self.target.mssql_db, self.target.username, self.target.password, self.target.domain, hashes=self.target.hashes, useWindowsAuth=self.target.windows_auth)

            if success:
                self.db_user = self.connection.RunSQLQuery(self.target.mssql_db, 'select current_user as "username"')[0]["username"]
                logging.info("  -  Login: successful (as %s)" % self.target.username)
                logging.info("  -  DB user: %s" % self.db_user)
                logging.info("  -  Database: %s" % self.connection.currentDB)
            else:
                logging.info("  -  Login: failed (as %s, reason: %s)" % (self.target.username, self.connection.replies[TDS_ERROR_TOKEN][0]['MsgText'].decode('utf-16le')))

            return success
        except Exception as e:
            logging.debug("Exception in checkConnection:", exc_info=True)
            logging.error(str(e))
            return False

    def checkEncryption(self):
        try:
            prelogin = TDS_PRELOGIN()
            prelogin['Version'] = b"\x08\x00\x01\x55\x00\x00"
            prelogin['Encryption'] = TDS_ENCRYPT_NOT_SUP
            prelogin['ThreadID'] = struct.pack('<L', random.randint(0, 65535))
            prelogin['Instance'] = b'MSSQLServer\x00'

            self.connection.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0)
            tds = self.connection.recvTDS()
            response = TDS_PRELOGIN(tds['Data'])
            version = MSSQL_VERSION(response['Version'])
            encryption = ("not " if response['Encryption'] == TDS_ENCRYPT_NOT_SUP else "") + "enforced"
            logging.info("%s (%s:%s)" % (self.target.remote_name, self.target.target_ip, self.target.mssql_port))
            logging.info("  -  Version: %s" % version)
            logging.info("  -  Encryption: %s" % encryption)

            self.disconnect()
        except Exception as e:
            logging.debug("Exception in checkEncryption:", exc_info=True)
            logging.error(str(e))


def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options)
    del options.target

    check = Check(target)
    check.check()
