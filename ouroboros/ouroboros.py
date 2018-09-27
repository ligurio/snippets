#!/usr/bin/env python

import cs
import io
import os
import pickle
import socket
import time
from paramiko.client import SSHClient, AutoAddPolicy
from paramiko.rsakey import RSAKey

DEF_DISTRIBUTION = 'OpenBSD 6.2 64-bit'
DEF_SIZE = 50
DEF_ZONE = 'ch-dk-2'
DEF_SERVICE_OFFERING = 'Small'
DEF_SEC_NAME = 'sg-test'
DEF_KEYPAIR = 'kp-test'


class Instance(distribution=DEF_DISTRIBUTION,
               size=DEF_SIZE,
               zone=DEF_ZONE,
               service_offering=DEF_SERVICE_OFFERING,
               security_group=DEF_SEC_NAME,
               keypair=DEF_KEYPAIR):

    def __init__():

        self.cloudstack = cs.CloudStack(**cs.read_config())
        self.distribution = distribution
        self.zone_name = zone
        self.service_offering_name = service_offering
        self.security_group_name = security_group
        self.keypair_name = keypair
        self.instance = None

        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())

        service_offering = cloudstack.listServiceOfferings()[
            'serviceoffering'][0]['id']
        security_group = create_sec_group()
        zoneid = get_zone_id()
        keypair = create_keypair()
        template = get_template()

    def create_sec_group():

        g = self.cloudstack.createSecurityGroup(name=name)['securitygroup']
        self.cloudstack.authorizeSecurityGroupIngress(icmptype=8,
                                                      icmpcode=0,
                                                      protocol="ICMP",
                                                      cidrlist="0.0.0.0/0",
                                                      securitygroupid=g['id'])
        self.cloudstack.authorizeSecurityGroupIngress(protocol="TCP",
                                                      cidrlist="0.0.0.0/0",
                                                      startport=22,
                                                      endport=22,
                                                      securitygroupid=g['id'])

        return g['id']

    def remove_sec_group(group_id):

        return cloudstack.deleteSecurityGroup(id=group_id)

    def create_keypair(name):

        keypair = cloudstack.createSSHKeyPair(name=name)['keypair']
        return keypair

    def remove_keypair(name):

        return cloudstack.deleteSSHKeyPair(name=name)

    def get_zone_id(zone):

        for z in cloudstack.listZones()['zone']:
            if z['name'] == zone:
                logger.info("Zone ID is {}".format(z['id']))
                return z['id']

    def get_template(distribution, size, zoneid):

        templates = cloudstack.listTemplates(templatefilter='featured',
                                             zoneid=zoneid)['template']
        templates = [t for t in templates
                     if t['name'] == distribution and
                     int(t['size'] / 1024 / 1024 / 1024) == size]

        return templates[0]['id']

    def create(name="ouroboros"):
        # keypair, serviceofferingid, securitygroupid, templateid, zoneid

        return cloudstack.deployVirtualMachine(
            serviceofferingid=serviceofferingid,
            templateid=templateid,
            zoneid=zoneid,
            displayname="{}-{}".format(name, os.getpid()),
            securitygroupids=[securitygroupid],
            keypair=keypair['name'],
            name="{}-{}".format(name, os.getpid()))

    def remove():

        # FIXME
        return True

    def spawn():

        now = time.time()
        while True:
            j = cloudstack.queryAsyncJobResult(jobid=self.instance['jobid'])
            if j['jobstatus'] != 0:
                if j['jobresultcode'] != 0 or j['jobstatus'] != 1:
                    raise RuntimeError(
                        'VM was not spawned successfully: {}'.format(j))
                if 'jobresult' not in j:
                    raise RuntimeError(
                        'No result after spawning the VM: {}'.format(j))
                v = j['jobresult']['virtualmachine']
                v['ipaddress'] = v['nic'][0]['ipaddress']
                time.sleep(2)       # Let the VM settle
                return v
            time.sleep(1)
            if time.time() - now > 60:
                raise RuntimeError(
                    'Unable to spawn VM due to timeout: {}'.format(j))

        self.is_running()

        return v
        # teardown: cloudstack.destroyVirtualMachine(id=v['id'])

    def is_running():

        now = time.time()
        while True:
            try:
                socket.create_connection(
                    (self.instance['ipaddress'], 22), timeout=10)
            except socket.error:
                if time.time() - now < 120:
                    continue
                raise
            break

    def console():

        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(self.instance['ipaddress'],
                           username="root",
                           timeout=10,
                           password=self.instance['password'],
                           allow_agent=False,
                           look_for_keys=False)
            return client

    def test_connect_with_key():

        sshclient.connect(self.instance['ipaddress'],
                          username="root",
                          timeout=10,
                          pkey=RSAKey.from_private_key(
                              io.StringIO(keypair['privatekey'])),
                          allow_agent=False,
                          look_for_keys=False)
        stdin, stdout, stderr = console.exec_command('echo hello')
        stdin.close()
        assert stdout.read() == b"hello\n"
        assert stderr.read() == b""

    def test_connect_with_password(sshvm):

        stdin, stdout, stderr = console.exec_command('echo hello')
        stdin.close()
        assert stdout.read() == b"hello\n"
        assert stderr.read() == b""

    def exec_command(instance, cmd):

        now = time.time()
        stdin, stdout, stderr = self.instance.exec_command(cmd)
        stdin.close()
        logger.info(time.time() - now)


class Config(config_path):

    def __init__():

        self.path = config_path

    def load():

        with open(self.path, 'rb') as conf:
            config = json.load(conf)
            return config


class History(history_file):

    def __init__():

        self.history_file = history_file

    def load():

        objects = []
        with (open(self.history_file, "rb")) as h:
            while True:
                try:
                    objects.append(pickle.load(h))
                except EOFError:
                    break

    def save():

        pass

    def append():

        pass


def main():

    c = Config('ouroboros-config.json')
    h = History(c['history_file'])
    for j in c['jobs']:
        worker = Instance()
        stdout, stderr = worker.exec_commands(j['cmd'])
        h.append(j['name'], stdout, stderr)
        worker.teardown()
    h.save()


if __name__ == '__main__':
    main()
