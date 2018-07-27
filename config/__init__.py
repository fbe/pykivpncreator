import subprocess, os, sys, json, netaddr
from netaddr import IPNetwork, IPAddress
from jsonschema import Draft4Validator

class VPNClient:
    def __init__(self, name, ip):
       self.name = name
       self.ip = ip

    def __str__(self):
        return "VPN Client '{}': [ ip: {} ]".format(self.name, self.ip)

class VPNServerConfig:
    def __init__(self, config_json, profile_name, append_domain):
        self.name = "{}-vpnhost".format(profile_name) if not "name" in config_json else config_json["name"]
        if append_domain:
            self.name = "{}.{}".format(self.name, append_domain)

        self.port = 1194 if not "port" in config_json else config_json["port"]
        self.subnet = IPNetwork("172.16.10.1/24") if not "subnet" in config_json else IPNetwork(config_json["subnet"])
        self.proto = "udp6" if not "proto" in config_json else config_json["proto"]

    def __str__(self):
        return "Name: {}, Port: {}, Subnet: {}".format(self.name, self.port, self.subnet)

class VPNConfig:
    def __init__(self, config_json, profile_name):
       self.append_domain = None if not "append_domain" in config_json else config_json["append_domain"] 
       self.server_config = VPNServerConfig(config_json["server_config"], profile_name, self.append_domain)
       self.clients = [] if not "clients" in config_json else self.parse_clients(config_json, self.server_config, self.append_domain)

    def parse_clients(self, config_json, server_config, append_domain):
        clients = []

        # Step 1: Collect all clients with a defined ip (and check if the ip fits to the subnet of the server config
        # Step 2: Build client list and set ip from remaining addresses
        taken_ip_addresses = [ 
            IPAddress(server_config.subnet[0]), # net address (reserved)
            IPAddress(server_config.subnet[1]), # VPN host (reserved)
            IPAddress(server_config.subnet[-1]), # broadcast (reserved)
        ]

        # 1
        for client in config_json["clients"]:
            if "ip" in client:
                ip = IPAddress(client["ip"])
                if ip not in server_config.subnet:
                    raise Exception("Configured client ip {} doesn't fit to subnet {}".format(ip, server_config.subnet))
                if ip in taken_ip_addresses:
                    raise Exception("Configured client ip {} is already in use or reserved!".format(ip))

                print("Found fixed valid ip for client {} - IP: {}".format(client["name"], ip))
                taken_ip_addresses.append(ip)

        # 2 - Build clients and use free remaining ip addresses
        for client in config_json["clients"]:
            name = client["name"]
            if append_domain:
                name = "{}.{}".format(name, append_domain)
            if not "ip" in client:
                free_addresses = set(server_config.subnet) - set(taken_ip_addresses)
                if not free_addresses:
                    raise Exception("Cannot find a free address in subnet {} - Taken ip addresses: {}".format(server_config.subnet, taken_ip_addresses))
                ip = list(free_addresses)[0] 
                taken_ip_addresses.append(ip)
            else: 
                ip = IPAddress(client["ip"])

            clients.append(VPNClient(name, ip))
        return clients

    def __str__(self):
        return "VPNConfig: Server Config: {}, Clients: {}".format(self.server_config, list(map(str, self.clients)))

class CAConfig:
    def __init__(self, config_json, profile_name):
        print("Initializing CAConfig")
        self.cn_name = "CA for Profile {}".format(profile_name) if not "cn_name" in config_json else config_json["cn_name"]

    def __str__(self):
         return "CAConfig: CA Common Name: {}".format(self.cn_name)

class ScriptConfig:
    def __init__(self, config_json):
        print("Loading ScriptConfig")
        self.use_git = False if not "use_git" in config_json else config_json["use_git"]
        self.easy_rsa_version = "3.0.4" if not "easy_rsa_version" in config_json else config_json["easy_rsa_version"]
        self.key_size = 4096  if not "key_size" in config_json else config_json["key_size"]
        # TODO add assertins with meaningful errors.

    def __str__(self):
         return "ScriptConfig: Use git: {}, Easy RSA Version: {}, Key Size: {}".format(self.use_git, self.easy_rsa_version, self.key_size)




class Config:
    def __init__(self, profile_name):
        print("Loading configuration for profile {}".format(profile_name))
        config_json_file = "{}.json".format(profile_name)
        if not os.path.exists(config_json_file):
            sys.exit("Expected profile config {} not found - aborting!".format(config_json_file))

        with open(config_json_file, 'r') as cjf:
            raw_json = cjf.read() 
            self.validate_json(raw_json)
            
            config_json = json.loads(raw_json)
            self.script_config = ScriptConfig(config_json["script_config"])
            self.vpn_config = VPNConfig(config_json["vpn_config"], profile_name)
            self.ca_config = CAConfig(config_json["ca_config"], profile_name)

            print(self.script_config)
            print(self.ca_config)
            print(self.vpn_config)

    def validate_json(self, json):
        with open("config/profilejson.schema.json", 'r') as schema_json_file:
            schema_json = schema_json_file.read() 
            print("Warning, schema validation disabled!")
            #Draft4Validator.check_schema(schema_json)
            #Draft4Validator(schema_json).validate(json)
