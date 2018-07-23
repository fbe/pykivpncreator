#!/usr/bin/python3

import subprocess, os, sys, re, tarfile, distutils.spawn, json, netaddr, shutil
from netaddr import IPNetwork, IPAddress
from config import Config

def read_file(fn):
    with open(fn, 'r') as f:
        return f.read()

def write_file(fn, content):
    folder_name = os.path.dirname(fn)
    if folder_name and not os.path.exists(folder_name):
        os.makedirs(folder_name)

    with open(fn, 'w') as f:
        f.write(content)

    print("Wrote file {}".format(fn))

class Profile:
    
    def __init__(self, profile_name):
        if not re.match(r"^[a-z]+$", profile_name):
            sys.exit("Illegal profile name {} - allowed regex is ^[a-z]+$".format(profile_name))

        self.profile_name = profile_name
        self.config = Config(self.profile_name)

        # for all client configs check if IPAddress in IPNetwork 

        self.profile_dir = "{}.profile".format(self.profile_name)
        self.pki_dir = "{}/pki/".format(self.profile_dir)
        self.easy_rsa_dir = "{}/EasyRSA-{}".format(self.profile_dir, self.config.script_config.easy_rsa_version)
        self.easy_rsa_executable = "{}/easyrsa".format(self.easy_rsa_dir)

        print("Easy RSA dir: {}".format(self.easy_rsa_dir))
        print("Easy RSA executable: {}".format(self.easy_rsa_executable))


    def check_or_initialize_dir(self, dir_name, initfunction):
        if not os.path.isdir(dir_name):
            print("Creating directory {} because it doesn't exist".format(dir_name))
            os.makedirs(dir_name)
            print("Initializing contents of dir {}".format(dir_name))
            initfunction(dir_name)

    def check_or_initialize_file(self, file_name, initfunction):
        if not os.path.exists(file_name):
            print("Initializing file {}".format(file_name))
            initfunction(file_name)

    def pki_file(self, filename):
        return "{}/{}".format(self.pki_dir, filename)

    def safe_call(self, command, env=os.environ):
        run = subprocess.call(command)
        if run == 0:
            print("Command successful...")
        else:
            sys.exit("Command '{}' failed - aborting!".format(" ".join(command)))

    def docker_container_call(self, command):
        self.safe_call(["docker", "run", "--rm", "-v", "{}/{}:/mnt/host".format(os.getcwd(), self.profile_dir), "-w", "/mnt/host/", "alpine"] + command )

    def easy_rsa(self, commands):
        batch_environment=os.environ
        batch_environment["EASYRSA_NO_VARS"] = "true"
        batch_environment["EASYRSA_BATCH"] = "true"
        self.safe_call([self.easy_rsa_executable]+commands, batch_environment)

    # 1
    def create_profile_dir(self):
        self.check_or_initialize_dir(self.profile_dir, lambda d: None)

    # 2 ta.key
    def create_ta_key(self):
        self.check_or_initialize_file("{}/ta.key".format(self.profile_dir), lambda f: self.docker_container_call(["sh", "-c", "apk add --no-cache openvpn && openvpn --genkey --secret ta.key && chown 1000:1000 ta.key;"]))

    # 3 extract easy rsa in profile dir
    def extract_easy_rsa(self):
        self.check_or_initialize_dir(self.easy_rsa_dir, lambda d: tarfile.open("assets/EasyRSA-{}.tgz".format(self.config.script_config.easy_rsa_version)).extractall(path=self.profile_dir))

    # 4 init-pki
    def init_pki(self): 
        self.check_or_initialize_dir(self.pki_dir, lambda d: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "init-pki"]))

    # 5 create ca
    def build_ca(self):
        self.check_or_initialize_file(self.pki_file("ca.crt"), lambda f: self.easy_rsa(["--keysize={}".format(self.config.script_config.key_size), "--pki-dir={}".format(self.pki_dir), "--req-cn={}".format(self.config.ca_config.cn_name), "build-ca", "nopass"]))

    # 6 Create CSRs
    def create_csrs(self):
        for csr in [self.config.vpn_config.server_config.name]+list(map(lambda x: x.name, self.config.vpn_config.clients)):
            self.check_or_initialize_file(self.pki_file("reqs/{}.req".format(csr)), lambda f: self.easy_rsa(["--keysize={}".format(self.config.script_config.key_size), "--pki-dir={}".format(self.pki_dir), "--req-cn={}".format(csr), "gen-req", "{}".format(csr), "nopass"]))

    # 7 Issue server:
    def issue_server(self):
        self.check_or_initialize_file(self.pki_file("issued/{}.crt".format(self.config.vpn_config.server_config.name)), lambda f: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "sign-req", "server", self.config.vpn_config.server_config.name]))

    # 8 Issue client(s):
    def issue_clients(self):
        for client in self.config.vpn_config.clients:
            self.check_or_initialize_file(self.pki_file("issued/{}.crt".format(client.name)), lambda f: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "sign-req", "client", client.name]))

    # 9 Create dh.pem
    def create_dh_secret(self):
        self.check_or_initialize_file(self.pki_file("dh.pem"), lambda f: self.easy_rsa(["--keysize={}".format(self.config.script_config.key_size), "--pki-dir={}".format(self.pki_dir), "gen-dh"]))

    # 10 Create client bundles
    def create_client_bundles(self):
        for client in self.config.vpn_config.clients:
            client_tmpl = read_file("assets/client.conf.tmpl")
            client_tmpl = client_tmpl.replace('{{serverport}}', str(self.config.vpn_config.server_config.port))
            client_tmpl = client_tmpl.replace('{{serveraddress}}', self.config.vpn_config.server_config.name)
            client_tmpl = client_tmpl.replace('{{cacert}}', read_file("{}/pki/ca.crt".format(self.profile_dir)))
            client_tmpl = client_tmpl.replace('{{cert}}', read_file("{}/pki/issued/{}.crt".format(self.profile_dir, client.name)))
            client_tmpl = client_tmpl.replace('{{privatekey}}', read_file("{}/pki/private/{}.key".format(self.profile_dir, client.name)))
            client_tmpl = client_tmpl.replace('{{takey}}', read_file("{}/ta.key".format(self.profile_dir)))
            write_file("{}/bundles/clients/{}/{}.conf".format(self.profile_dir, client.name, client.name), client_tmpl)

    
    # 11 Create server bundles
    def create_server_bundle(self):
        server_conf_tmpl = read_file("assets/server.conf.tmpl")
        server_conf_tmpl = server_conf_tmpl.replace('{{server_port}}', str(self.config.vpn_config.server_config.port))
        server_conf_tmpl = server_conf_tmpl.replace('{{server_proto}}', self.config.vpn_config.server_config.proto)
        server_conf_tmpl = server_conf_tmpl.replace('{{server_cert}}', "{}.crt".format(self.config.vpn_config.server_config.name))
        server_conf_tmpl = server_conf_tmpl.replace('{{server_key}}', "{}.key".format(self.config.vpn_config.server_config.name))
        server_conf_tmpl = server_conf_tmpl.replace('{{server_subnet_netaddr}}', str(self.config.vpn_config.server_config.subnet[0]))
        server_conf_tmpl = server_conf_tmpl.replace('{{server_subnet_netmask}}', str(self.config.vpn_config.server_config.subnet.netmask))
        write_file("{}/bundles/server/{}.conf".format(self.profile_dir, self.config.vpn_config.server_config.name), server_conf_tmpl)
        for file_name in [ 
            "pki/issued/{}.crt".format(self.config.vpn_config.server_config.name), 
            "pki/private/{}.key".format(self.config.vpn_config.server_config.name), 
            "pki/dh.pem", 
            "ta.key",
            "pki/ca.crt"
        ]:
            shutil.copy2("{}/{}".format(self.profile_dir, file_name),"{}/bundles/server/".format(self.profile_dir))
        for client in self.config.vpn_config.clients:
            ccd_push = "ifconfig-push {} {}".format(str(client.ip), str(self.config.vpn_config.server_config.subnet.netmask))
            write_file("{}/bundles/server/ccd/{}".format(self.profile_dir, client.name), ccd_push)

def assert_preconditions():
    if not distutils.spawn.find_executable("docker"):
        sys.exit("Cannot find docker executable - docker is mandatory for running this script")


if __name__ == "__main__":
    
    assert_preconditions()

    if len(sys.argv) != 2:
        sys.exit("Usage: {} <profilename>".format(sys.argv[0]))

    profile = Profile(sys.argv[1])
    profile.create_profile_dir()
    profile.create_ta_key()
    profile.extract_easy_rsa()
    profile.init_pki()
    profile.build_ca()
    profile.create_csrs()
    profile.issue_server()
    profile.issue_clients()
    profile.create_dh_secret()
    profile.create_client_bundles()
    profile.create_server_bundle()
