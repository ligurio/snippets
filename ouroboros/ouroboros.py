#!/usr/bin/env python

import io
import os
import pickle
import random
import logging
import socket
import time
import json

from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.compute.deployment import ScriptDeployment
from libcloud.compute.ssh import ParamikoSSHClient

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('ouroboros')
logger.setLevel(logging.INFO)

class Instance():

    DEF_DISTRIBUTION = 'OpenBSD 6.3 64-bit'
    DEF_SIZE = 'Micro'

    PUBLIC_KEY_FILE = os.path.expanduser('~/.ssh/id_rsa.pub')
    PRIVATE_KEY_FILE = os.path.expanduser('~/.ssh/id_rsa_com')

    def __init__(self):

        self.API_KEY = os.getenv('API_KEY')
        self.API_SECRET_KEY = os.getenv('API_SECRET_KEY')

        self.node = None
        self.hostname = None
        self.port = 22
        self.username = 'root'
        self.password = None
        self.key_pair = None
        self.timeout = 60

        self.conn = get_driver(Provider.EXOSCALE)
        self.driver = self.conn(self.API_KEY, self.API_SECRET_KEY)

    def create_key_pair(self):

        # TODO: self.key_pair = self.conn.create_key_pair(name='ouroboros-key-pair')
        if os.path.exists(self.PUBLIC_KEY_FILE):
            self.key_pair = self.driver.import_key_pair_from_file(name='ouroboros-key-pair',
                                                        key_file_path=self.PUBLIC_KEY_FILE)

    def create(self):

        if not self.API_KEY or not self.API_SECRET_KEY:
            logger.warning("API_SECRET_KEY and API_KEY are not found")
            return None

        size = [size for size in self.driver.list_sizes() if size.name == self.DEF_SIZE][0]
        logger.info("size %s" % size)
        image = [image for image in self.driver.list_images() if self.DEF_DISTRIBUTION in image.name][0]
        logger.info("image %s" % image)

        self.create_key_pair()

        name = "{}-{}-{}".format("ouroboros-node", os.getpid(), str(random.randint(0, 100)))
        logger.info("name %s" % name)
        try:
            logger.info("create instance")
            self.node = self.driver.deploy_node(name=name, image=image, size=size,
                                              ex_keyname=self.key_pair.name,
                                              ssh_key_file=self.PUBLIC_KEY_FILE)
        except Exception as e:
            print e
            self.driver.delete_key_pair(key_pair=self.key_pair)
            return e

    def teardown(self):

        logger.info("Teardown instance")
        # TODO: self.key_pair.delete_key_pair()
        self.node.destroy_node()

    def is_running():

        now = time.time()
        while True:
            try:
                socket.create_connection((self.hostname, 22), timeout=self.timeout)
            except socket.error:
                if time.time() - now < 120:
                    continue
                raise
            break

    def exec_commands(self, commands):

        stdout_common = ""
        stderr_common = ""
        exit_status_common = 0
        for c in commands:
            stdout, stderr, exit_status = self.exec_command(c)
            stdout_common += str(stdout)
            stderr_common += str(stderr)
            if exit_status != 0:
                exit_status_common = exit_status
                break

        return stdout_common, stderr_common, exit_status_common

    def exec_command(self, cmd):

        client = ParamikoSSHClient(hostname=self.hostname, port=self.port,
                                username=self.username, password=self.password,
                                key=[self.PRIVATE_KEY_FILE], timeout=self.timeout)
        #if client.connect():
        #    stdout, stderr, exit_status = client.run(cmd)
        #    client.close()
        #    return stdout, stderr, exit_status
        #else:
        #    return None, None, None
        return None, None, None


class Config():

    def __init__(self, config_path):

        self.path = config_path

    def load(self):

        with open(self.path, 'rb') as conf:
            config = json.load(conf)
            return config

def main():

    c = Config('ouroboros-config.json').load()
    for j in c['jobs']:
        logger.info("Running job: %s", j['name'])
        worker = Instance()
        worker.create()
        stdout, stderr, exit_status = worker.exec_commands(j['cmd'])
        logger.info("Finished job %s, exit status %s", j['name'], str(exit_status))
        worker.teardown()

if __name__ == '__main__':
    main()
