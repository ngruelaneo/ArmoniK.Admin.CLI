"""ArmoniK Admin CLI to perform admnistration tasks for ArmoniK

Usage:
  armonik.py cancel-session list <session>... [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py cancel-session --running         [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py cancel-task <task>...            [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE]
  armonik.py list-task <session>...           [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE] [--all | --creating | --error]
  armonik.py list-session                     [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE] [--all | --running | --cancelled]
  armonik.py list-result                      [--endpoint ENDPOINT] [--ca CA_FILE] [--cert CERT_FILE] [--key KEY_FILE] [--all]
  armonik.py (-h | --help)
  armonik.py --version
  armonik.py check-task <taskid>


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
  --error                           Select error tasks
"""

from docopt import docopt
import grpc
import math
from armonik.client.sessions import ArmoniKSessions, SessionFieldFilter
from armonik.client.tasks import ArmoniKTasks, TaskFieldFilter
from armonik.client.results import ArmoniKResult, ResultFieldFilter
from armonik.common.enumwrapper import TASK_STATUS_ERROR, TASK_STATUS_COMPLETED, TASK_STATUS_CREATING , SESSION_STATUS_RUNNING, SESSION_STATUS_CANCELLED, SESSION_STATUS_UNSPECIFIED, RESULT_STATUS_ABORTED, RESULT_STATUS_COMPLETED, RESULT_STATUS_CREATED, RESULT_STATUS_NOTFOUND, RESULT_STATUS_UNSPECIFIED


def create_channel(arguments):
    """
    Create a gRPC channel for communication with the ArmoniK control plane

    Args:
        arguments (dict): command-line arguments from docopt

    Returns:
        grpc.Channel: gRPC channel for communication
    """
    if(arguments["--ca"] != None and arguments["--cert"] != None and arguments["--key"] != None):
        ca = open(arguments["--ca"], 'rb').read()
        cert = open(arguments["--cert"], 'rb').read()
        key = open(arguments["--key"], 'rb').read()
        credentials = grpc.ssl_channel_credentials(ca, key, cert)
        return grpc.secure_channel(arguments["--endpoint"], credentials)
    else:
        return grpc.insecure_channel(arguments["--endpoint"])


def list_sessions(client: ArmoniKSessions, all: bool, running: bool, cancelled: bool):
    """
    List sessions with filter options

    Args:
        client (ArmoniKSessions): ArmoniKSessions instance for session management
        all (bool): Show all sessions
        running (bool): Show only running sessions
        cancelled (bool): Show only cancelled sessions
    """
    session_filter = None

    if all:
        session_filter = (SessionFieldFilter.STATUS == SESSION_STATUS_RUNNING) | (SessionFieldFilter.STATUS == SESSION_STATUS_CANCELLED)
    elif running:
        session_filter = SessionFieldFilter.STATUS == SESSION_STATUS_RUNNING
    elif cancelled:
        session_filter = SessionFieldFilter.STATUS == SESSION_STATUS_CANCELLED
    else:
        print("SELECT ARGUMENT [--all | --running | --cancelled]")
        return

    page = 0
    while True:
        number_sessions, sessions = client.list_sessions(session_filter, page=page)

        if len(sessions) == 0:
            break

        for session in sessions:
            print(f'Session ID: {session.session_id}')
        
        page += 1

    print(f'\nNumber of sessions: {number_sessions}\n')



def cancel_sessions(client: ArmoniKSessions, sessions: list):
    """
    Cancel sessions with a list of session IDs or all sessions running

    Args:
        client (ArmoniKSessions): Instance of the class with cancel_session method
        sessions (list): List of session IDs to cancel
    """
    if sessions:
        for session_id in sessions:
            client.cancel_session(session_id)


def list_tasks(client: ArmoniKTasks, session_ids: list, all: bool, creating: bool , error: bool):
    """
    List tasks associated with the specified sessions based on filter options

    Args:
        client (ArmoniKTasks): ArmoniKTasks instance for task management
        session_ids (list): List of session IDs to filter tasks
        all (bool): List all tasks regardless of status
        creating (bool): List only tasks in creating status
        error (bool): List only tasks in error status
    """
    for session_id in session_ids:
        page = 0
        while True:
            if all:
                tasks_filter = TaskFieldFilter.SESSION_ID == session_id
            elif creating:
                tasks_filter = (TaskFieldFilter.SESSION_ID == session_id) & (TaskFieldFilter.STATUS == TASK_STATUS_CREATING)
            elif error:
                tasks_filter = (TaskFieldFilter.SESSION_ID == session_id) & (TaskFieldFilter.STATUS == TASK_STATUS_ERROR)
            else:
                print("SELECT ARGUMENT [--all | --creating | --error]")
                return

            nb_tasks, task_list = client.list_tasks(tasks_filter, page=page)

            if len(task_list) == 0:
                break

            for task in task_list:
                print(f'Task ID: {task.id}')
            
            page += 1
        
        print(f"\nTotal tasks: {nb_tasks}\n")

def check_task(client: ArmoniKTasks, task_id: str):
    """
    Check the status of a task based on its ID.

    Args:
        client (ArmoniKTasks): ArmoniKTasks instance for task management.
        task_id (str): ID of the task to check.
    """
    _, task_list = client.list_tasks(TaskFieldFilter.TASK_ID == task_id)
    if len(task_list) > 0:
        print(f"\nTask information for task ID {task_id} :\n")
        print(task_list)
    else:
        print(f"No task found with ID {task_id}")


def main():
    arguments = docopt(__doc__, version="ArmoniK Admin CLI  0.0.1")
    grpc_channel = create_channel(arguments)
    session_client = ArmoniKSessions(grpc_channel)
    task_client = ArmoniKTasks(grpc_channel)
    result_client = ArmoniKResult(grpc_channel)

    if arguments['list-session']:
        list_sessions(session_client, arguments["--all"], arguments["--running"], arguments["--cancelled"])

    if arguments['list-task']:
        session_ids = arguments["<session>"]
        list_tasks(task_client, session_ids, arguments["--all"], arguments["--creating"], arguments["--error"])

    if arguments['check-task']:
        task_id = arguments["<taskid>"]
        check_task(task_client, task_id)

    if arguments['cancel-session']:
        if arguments["list"]:
            cancel_sessions(session_client, arguments["<session>"])
        if arguments["--running"]:
            _, session_list = session_client.list_sessions(SessionFieldFilter.STATUS == SESSION_STATUS_RUNNING)
            session_ids = [session.session_id for session in session_list]
            cancel_sessions(session_client, session_ids)
    
    if arguments['list-result']:
        number_results, results = result_client.list_results(ResultFieldFilter.STATUS == RESULT_STATUS_COMPLETED)
        print(f'Number of results: {number_results}\nResults: {[result.result_id for result in results]}')
        for result in results:
            print(f"Result ID: {result.result_id}")

if __name__ == '__main__':
    main()
