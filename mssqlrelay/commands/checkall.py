import argparse
from typing import List

from mssqlrelay.commands.check import Check
from mssqlrelay.lib.target import Target
from mssqlrelay.lib.ldap import LDAPConnection, LDAPEntry
from mssqlrelay.lib.logger import logging

class MSSQLInstance:
    def __init__(self, serviceAccount, spn):
        self.serviceAccount = serviceAccount
        self.spn = spn
        self.instance = spn.split("/")[1]
        try:
            self.hostname = self.instance.split(":")[0]
        except ValueError:
            self.hostname = self.instance
        try:
            self.port = self.instance.split(":")[1]
        except:
            self.port = 1433


class CheckAll:
    def __init__(
            self,
            target: Target,
            scheme: str = "ldaps",
            connection: LDAPConnection = None):
        self.target = target
        self.scheme = scheme
        self._connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self._connection is not None:
            return self._connection

        self._connection = LDAPConnection(self.target, self.scheme)
        self._connection.connect()

        return self._connection

    def get_domain_mssql_instances(self) -> List[MSSQLInstance]:
        filter_spn = "servicePrincipalName=MSSQL*"
        filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

        searchFilter = "(&"
        searchFilter += "(" + filter_not_disabled + ")"
        searchFilter += "(" + filter_spn + ")"
        searchFilter += ')'

        serviceAccounts = self.connection.search(
            searchFilter,
            search_base=self.connection.default_path,
            attributes=[
                "servicePrincipalName",
                "sAMAccountName",
                "pwdLastSet",
                "MemberOf",
                "userAccountControl",
                "lastLogon"
            ],
            query_sd=True,
        )

        instances = list()

        for serviceAccount in serviceAccounts:
            for spn in serviceAccount.get("servicePrincipalName"):
                instances.append(MSSQLInstance(serviceAccount.get("sAMAccountName"), spn))

        return instances

    def checkall(self):
        instances = self.get_domain_mssql_instances()
        logging.info("SPNs in domain %s:" % self.target.domain)
        for instance in instances:
            logging.info("  - %s (running as %s)" % (instance.spn, instance.serviceAccount))
        logging.info("Checking found instances ...")
        for instance in instances:
            check = Check(
                Target.create(
                    self.target.domain,
                    self.target.username,
                    self.target.password,
                    self.target.hashes,
                    remote_name=instance.hostname,
                    do_kerberos=self.target.do_kerberos,
                    use_sspi=self.target.use_sspi,
                    windows_auth=self.target.windows_auth,
                    aes=self.target.aes,
                    dc_ip=self.target.dc_ip,
                    mssql_port=instance.port
                )
            )
            check.check()

def entry(options: argparse.Namespace) -> None:
    target = Target.from_options(options, dc_as_target=True)
    del options.target

    checkall = CheckAll(target, options.scheme)
    checkall.checkall()
