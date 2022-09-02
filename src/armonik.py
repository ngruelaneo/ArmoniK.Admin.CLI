"""ArmoniK Admin CLI to perform admnistration tasks for ArmoniK

Usage:
  armonik.py cancel-session list <session>... [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py cancel-session running           [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py cancel-task <task>...            [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py list-task <session>...           [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE] [--all | --creating]
  armonik.py list-session                     [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE] [--all | --running | --cancelled]
  armonik.py (-h | --help)
  armonik.py --version

Options:
  -h --help                         Show this screen.
  --version                         Show version.
  -e ENDPOINT --endpoint ENDPOINT   ArmoniK control plane endpoint. [default: localhost:5001]
  --ca CA_FILE                      CA file for mutual tls
  --cert CERT_FILE                  Certificate for mutual tls
  --key KEY_FILE                    Private key for mutual tls
  --all                             Select all sessions or tasks
  --running                         Select running sessions
  --cancelled                       Select cancelled sessions
  --session SESSION                 Select tasks from SESSION
  --creating                        Select creating tasks
"""

from docopt import docopt
import grpc

import client.api.submitter_service_pb2_grpc as sub
import client.api.submitter_common_pb2 as subc
import client.api.objects_pb2 as obj
import client.api.session_status_pb2 as sessionStatus
from client.api.task_status_pb2 import TASK_STATUS_CREATING

def create_channel(arguments):
    if(arguments["--ca"] != None and arguments["--cert"] != None and arguments["--key"] != None):
        ca = open(arguments["--ca"], 'rb').read()
        cert = open(arguments["--cert"], 'rb').read()
        key = open(arguments["--key"], 'rb').read()
        credentials = grpc.ssl_channel_credentials(ca, key, cert)
        return grpc.secure_channel(arguments["--endpoint"], credentials)
    else:
        return grpc.insecure_channel(arguments["--endpoint"])

def __list_sessions(client, status):
    return client.ListSessions(subc.SessionFilter(included=subc.SessionFilter.StatusesRequest(statuses=[status])))

def __list_tasks(client, sessions, status):
    if(status == None):
        return client.ListTasks(subc.TaskFilter(session=subc.TaskFilter.IdsRequest(ids=sessions)))
    else:
        return client.ListTasks(subc.TaskFilter(session=subc.TaskFilter.IdsRequest(ids=sessions), included=subc.TaskFilter.StatusesRequest(statuses=[status])))

def __cancel_sessions(client, sessions):
    for s in sessions:
        client.CancelSession(obj.Session(id=s))

def __cancel_tasks_ids(client, tasks):
    client.CancelTasks(subc.TaskFilter(tasks=subc.TaskFilter.IdsRequest(ids=tasks)))

def list_sessions(client, all, running, cancelled):
    if(all or running):
        l = __list_sessions(client, sessionStatus.SESSION_STATUS_RUNNING)
        if(len(l.session_ids) > 0):
            print("running sessions :")
            print(l)
    if(all or cancelled):
        l = __list_sessions(client, sessionStatus.SESSION_STATUS_CANCELED)
        if(len(l.session_ids) > 0):
            print("cancelled sessions :")
            print(l)
    if(all):
        l = __list_sessions(client, sessionStatus.SESSION_STATUS_UNSPECIFIED)
        if(len(l.session_ids) > 0):
            print("unspecified sessions :")
            print(l)

def list_tasks(client, sessions, all, creating):
    if(all or creating):
        l = __list_tasks(client, sessions, TASK_STATUS_CREATING)
        if(len(l.task_ids) > 0):
            print("creating tasks :")
            print(l)
    if(all):
        l = __list_tasks(client, sessions, None)
        if(len(l.task_ids) > 0):
            print("all tasks :")
            print(l)

if __name__ == '__main__':
    arguments = docopt(__doc__, version='ArmoniK Admin CLI 0.0.1')
    print(arguments)
    client = sub.SubmitterStub(create_channel(arguments))

    if(arguments["list-session"]):
        list_sessions(client, arguments["--all"], arguments["--running"], arguments["--cancelled"])
    
    if(arguments["list-task"]):
        list_tasks(client, arguments["<session>"], arguments["--all"], arguments["--creating"])

    if(arguments["cancel-task"]):
        __cancel_tasks_ids(client, arguments["<task>"])

    if(arguments["cancel-session"]):
        if(arguments["list"]):
            __cancel_sessions(client, arguments["<session>"])
        if(arguments["running"]):
            l = __list_sessions(client, sessionStatus.SESSION_STATUS_RUNNING)
            if(len(l.session_ids) > 0):
                __cancel_sessions(client, l.session_ids)

