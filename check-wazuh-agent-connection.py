#!/usr/bin/env python3
import argparse
import json
import os
import sys
import requests  # To install requests, use: pip3 install requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class RequestWazuh:
    def __init__(self, host, tls_verify, search_limit=100):
        self.base_url = f"https://{host}:55000"
        self.verify = tls_verify
        self.search_limit = search_limit

    @staticmethod
    def auth(user, password):
        return requests.auth.HTTPBasicAuth(user, password)

    def url_path(self, __path):
        return f'{self.base_url}{"/agents"}{__path}'

    # Look for the Wazuh agent that is having connection problems.
    def get_agents_connection(self, __auth):
        return self.request(
            query=f"?pretty&offset=0&limit={self.search_limit}&sort=status",
            auth=__auth
        )

    @staticmethod
    def inactive_agent(arg):
        res = []

        # Like a $(jq '.data.items[]| select(.status != "Active")|{status: status, name: name, wazuh_id: id}')
        for item in arg["data"]["items"]:
            if item["status"] != "Active":
                res.append({"status": item["status"], "name": item["name"], "wazuh_id": item["id"]})
        return res

    def request(self, **kwargs):
        __query = kwargs["query"].replace("\n", "")
        url = self.url_path(f"/{__query}")

        try:
            return requests.get(url, auth=kwargs["auth"], params=None, verify=self.verify, timeout=5.00)
        except requests.exceptions.RequestException as e:
            raise str(e)
        finally:
            pass

    # If the agent was deleted, it return error: 1701
    def has_agent(self, agent_id, __auth):
        if json.loads(self.request(query=agent_id, auth=__auth).content)["error"] == 1701:
            return False

        return True

    @staticmethod
    def is_active(r, agent_id, __auth):
        __res = r.request(query=agent_id, auth=__auth)
        if json.loads(__res.content)["data"]["status"] == "Active":
            return True, None

        return False, json.loads(__res.content)["data"]["name"]

    @staticmethod
    def replace_file(id_file, **strings):
        with open(id_file, "r") as f:
            data_lines = f.read()
            data_lines = data_lines.replace(strings["org"], strings["replace"])
            f.close()

        with open(id_file, "w") as f:
            f.write(data_lines)
            f.close

    @staticmethod
    def has_erroneous_judgment(r, **kwargs):
        # Preparation: If already deleted agent after previous checks, will delete the ID in the inactive agent list.
        with open(kwargs["id_file"]) as f:
            for __agent_id in f.readlines():
                # [Memo] Wazuh's error number 1701 like a status code 404.
                # So we can't use the following condition.
                #   if not res.ok or res.status_code == 404:
                if not r.has_agent(__agent_id, kwargs["auth"]):
                    # Will delete agent id in inactive agent list
                    r.replace_file(kwargs["id_file"], org=__agent_id, replace="")

            del __agent_id
            f.close()

        # Is it really recovering?
        # Will check direct /agents/$ID and more with id list of inactive agents at last time.
        with open(kwargs["id_file"]) as f:
            for __agent_id in f.readlines():
                recovery_final_answer, agent = r.is_active(r, __agent_id, kwargs["auth"])
                if recovery_final_answer:
                    return False, None  # no erroneous judgment
                else:
                    # In final check, Are agents all actives? / no:
                    # Probably, there is like a false negative, so should be go back
                    # the 'check inactive agents' of monitoring process.
                    return True, f"{agent} is still inactive"

    @staticmethod
    def show_inactive_agents(r, json_data, id_file):
        alert_box = []
        for item in r.inactive_agent(json_data):
            # Create inactive agents list because it for prevent the erroneous determination of the
            # normality when final checks, and thus the accuracy of the normality determination is improved.
            # So that check at /agents/${ID} and more.
            with open(id_file, 'w') as f:
                f.write(f'{item["wazuh_id"]}\n')
                f.close()

            alert_box.append(item)

        if len(alert_box) >= 1:
            return True, alert_box
        else:
            return False, None


def main():
    if args.disable_warnings:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    r = RequestWazuh(args.host, args.tls_verify, 100)
    __auth = r.auth(args.user, args.password)
    # Health check
    # Are there inactive status agents? For example, Disconnected, Never disconnected, or other.
    res = r.get_agents_connection(__auth)
    res.raise_for_status()
    json_data = json.loads(res.content)
    agent_id_file = "/tmp/wazuh_inactive_agent_id.list"

    has_inactive_agents, alert_box = r.show_inactive_agents(
        r,
        json_data,
        agent_id_file
    )

    if has_inactive_agents:
        # Alert
        print(alert_box)
        exit(1)

    # If the agent that was determined to be abnormal last time does not exist, it ends normally.
    if not os.path.isfile(agent_id_file):
        exit(0)

    # If the agent_id_file exists and is empty, the file will be deleted.
    if os.stat(agent_id_file).st_size == 0:
        os.remove(agent_id_file)
        exit(0)

    # Final confirmation of the failed judged agent at past. Validate whether any of
    # erroneous determination of the normal.
    # Also, if a already deleted agent, remove id in the inactive agent id list file.
    misjudgment, msg = r.has_erroneous_judgment(r, id_file=agent_id_file, auth=__auth)

    if misjudgment:
        print(msg)
        exit(1)


class HostAction(argparse.Action):
    def __call__(self, __parser, namespace, values, option_string=None):
        if len(values) >= 1 and namespace.tls_verify is False:
            print("Recommended that together use of a --tls-verify option"
                  " because of detected use of the --host option.")

        namespace.host = values


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'{sys.argv[0]} is wazuh-agent connection checker.'
                                                 ' This tools prevent the erroneous determination of the normality'
                                                 ' when final checks, and thus the accuracy'
                                                 ' of the normality determination is improved.')

    parser.add_argument("-u", "--user", default='user', dest="user", type=str,
                        help="API user. (Default is user)")

    parser.add_argument("-p", "--password", default='pass', dest="password", type=str,
                        help="API password. (Default is pass)")

    parser.add_argument("-H", "--host", default='127.0.0.1', dest="host", type=str,
                        action=HostAction,
                        help="The Wazuh manager's hostname or IP address. (Default is 127.0.0.1)")

    parser.add_argument("-i", "--ignore-warning", default=False, action='store_true', dest="disable_warnings",
                        help="Can ignore InsecureRequestWarning for urllib3 exception. For example, host is 127.0.0.1. "
                             "https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings"
                             " (Default is False)")

    parser.add_argument("--tls-verify", default=False, action='store_true', dest="tls_verify",
                        help="TLS verify. The Wazuh's default setting API has a loopback address (127.0.0.1),"
                             " so you don't need to validate the certificate to access it by address,"
                             " but you can use this option If you want to perform server verification"
                             " when accessing from other servers. (Default is False)")

    args = parser.parse_args()
    main()
