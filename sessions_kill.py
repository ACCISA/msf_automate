import logging
from pymsf import RpcClient

client = RpcClient("yourpassword", ssl=True)

sessions = client.call("session.list")

for session in sessions.keys():
    logging.warning(client.call("session.stop",[session]))

logging.warning("sessions cleared")