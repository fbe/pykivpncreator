#!/usr/bin/python3

import subprocess, os, sys, re, tarfile

easy_rsa_version = "3.0.4"

class Profile:
    
    def __init__(self, profile_name, clients, servers, ca_cn_name):
        if not re.match(r"[a-z]+", profile_name):
            sys.exit("Illegal profile name {} - allowed regex is [a-z]+".format(profile_name))

        self.profile_name = profile_name
        self.profile_dir = "{}.profile".format(self.profile_name)
        self.pki_dir = "{}/pki/".format(self.profile_dir)
        self.easy_rsa_dir = "{}/EasyRSA-{}".format(self.profile_dir, easy_rsa_version)
        self.easy_rsa_executable = "{}/easyrsa".format(self.easy_rsa_dir)
        self.clients = clients
        self.servers = servers
        self.ca_cn_name = ca_cn_name

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
        self.check_or_initialize_dir(self.easy_rsa_dir, lambda d: tarfile.open("assets/EasyRSA-{}.tgz".format(easy_rsa_version)).extractall(path=self.profile_dir))

    # 4 init-pki
    def init_pki(self): 
        self.check_or_initialize_dir(self.pki_dir, lambda d: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "init-pki"]))

    # 5 create ca
    def build_ca(self):
        self.check_or_initialize_file(self.pki_file("ca.crt"), lambda f: self.easy_rsa(["--keysize=4096", "--pki-dir={}".format(self.pki_dir), "--req-cn={}".format(ca_cn_name), "build-ca", "nopass"]))

    # 6 Create CSRs
    def create_csrs(self):
        for csr in servers+clients:
            self.check_or_initialize_file(self.pki_file("reqs/{}.req".format(csr)), lambda f: self.easy_rsa(["--keysize=4096", "--pki-dir={}".format(self.pki_dir), "--req-cn={}".format(csr), "gen-req", "{}".format(csr), "nopass"]))

    # 7 Issue server(s):
    def issue_servers(self):
        for server in servers:
            self.check_or_initialize_file(self.pki_file("issued/{}.crt".format(server)), lambda f: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "sign-req", "server", server]))

    # 8 Issue client(s):
    def issue_clients(self):
        for client in clients:
            self.check_or_initialize_file(self.pki_file("issued/{}.crt".format(client)), lambda f: self.easy_rsa(["--pki-dir={}".format(self.pki_dir), "sign-req", "client", client]))

    # 9 Create dh.pem
    def create_dh_secret(self):
        self.check_or_initialize_file(self.pki_file("dh.pem"), lambda f: self.easy_rsa(["--keysize=4096", "--pki-dir={}".format(self.pki_dir), "gen-dh"]))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit("Usage: {} <profilename>".format(sys.argv[0]))

    # TODO from config / cmd line
    clients = list(map(lambda x: "{}.testdomain.de".format(x), ["notebook.interal", "hanspansen.internal", "raspberry.internal"]))
    servers = ["vpnhost.testdomain.de"]
    ca_cn_name="Meine CA"

    profile = Profile(sys.argv[1], clients, servers, ca_cn_name)
    profile.create_profile_dir()
    profile.create_ta_key()
    profile.extract_easy_rsa()
    profile.init_pki()
    profile.build_ca()
    profile.create_csrs()
    profile.issue_servers()
    profile.issue_clients()
    profile.create_dh_secret()
