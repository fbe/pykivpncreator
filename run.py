#!/usr/bin/python3

import subprocess, os, sys
import tarfile
from subprocess import call


profile=sys.argv[1]
profile_dir = "{}.profile".format(profile)
easy_rsa_version = "3.0.4"
pki_dir = "{}/pki/".format(profile_dir)
easy_rsa_dir = "{}/EasyRSA-{}".format(profile_dir, easy_rsa_version)
easy_rsa_executable = "{}/easyrsa".format(easy_rsa_dir)
clients = list(map(lambda x: "{}.testdomain.de".format(x), ["notebook.interal", "hanspansen.internal", "raspberry.internal"]))
servers = ["vpnhost.testdomain.de"]
servers_and_clients = clients+servers
ca_cn_name="Meine CA"

batch_environment=os.environ
batch_environment["EASYRSA_NO_VARS"] = "true"
batch_environment["EASYRSA_BATCH"] = "true"


if not os.path.isdir(profile_dir):
    print("Profile dir '{}' does not exist - creating...".format(profile_dir))
    os.makedirs(profile_dir)

takey_file = "{}/ta.key".format(profile_dir)

cwd = os.getcwd()

if not os.path.exists(takey_file):
    run_command = ["docker", "run", "--rm", "-v", "{}/{}:/mnt/host".format(cwd,profile_dir), "ubuntu:18.04", "bash", "-c", "apt-get update && apt-get -y install openvpn && cd /mnt/host && openvpn --genkey --secret ta.key && ls -la ta.key; chown 1000:1000 ta.key; ls -la ta.key"]
    call(run_command)


if not os.path.isdir(easy_rsa_dir):
    print("Extracting easya rsa")
    tar=tarfile.open("assets/EasyRSA-{}.tgz".format(easy_rsa_version))
    tar.extractall(path=profile_dir)
    

def check_or_initialize_dir(dir_name, initfunction):
    if not os.path.isdir(dir_name):
        print("Creating directory {} because it doesn't exist".format(dir_name))
        os.makedirs(dir_name)
        print("Initializing contents of dir {}".format(dir_name))
        initfunction(dir_name)

def check_or_initialize_file(file_name, initfunction):
    if not os.path.exists(file_name):
        print("Initializing file {}".format(file_name))
        initfunction(file_name)

def pki_file(filename):
    return "{}/{}".format(pki_dir, filename)

def easy_rsa(commands):
    call([easy_rsa_executable]+commands)

# what about that style? does that help / make the code more compact
check_or_initialize_dir(pki_dir, lambda d: easy_rsa(["--pki-dir={}".format(pki_dir), "init-pki"]))
check_or_initialize_file(pki_file("ca.crt"), lambda f: easy_rsa(["--keysize=4096", "--pki-dir={}".format(pki_dir), "--req-cn={}".format(ca_cn_name), "build-ca", "nopass"]))

for csr in servers_and_clients:
    check_or_initialize_file(pki_file("reqs/{}.req".format(csr)), lambda f: easy_rsa(["--keysize=4096", "--pki-dir={}".format(pki_dir), "--req-cn={}".format(csr), "gen-req", "{}".format(csr), "nopass"]))

for server in servers:
    check_or_initialize_file(pki_file("issued/{}.crt".format(server)), lambda f: easy_rsa(["--pki-dir={}".format(pki_dir), "sign-req", "server", server]))

for client in clients:
    check_or_initialize_file(pki_file("issued/{}.crt".format(client)), lambda f: easy_rsa(["--pki-dir={}".format(pki_dir), "sign-req", "client", client]))

check_or_initialize_file(pki_file("dh.pem"), lambda f: easy_rsa(["--keysize=4096", "--pki-dir={}".format(pki_dir), "gen-dh"]))
