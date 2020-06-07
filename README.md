check-wazuh-agent-connection
---------------------------

This monitoring tool check for the Wazuh agent connection in Wazuh manager.
If there are inactive/abnormal agents, it return exception and error code.
And it can prevent the erroneous determination of the normality, and thus the accuracy of the normality determination is improved.

## Requirements

- Python3
- pip3
  - requests

```sh
$ pip3 install -r requirements.txt
```

or

```sh
$ pip3 install requests
```


## Help / Usage

```sh
$ check-wazuh-agent-connection.py [-h|--help]
```


## Example

In the Wazuh manager.

### Normal

```sh
(venv) [k-oguma@ip-172-30-0-100 ~]$ ./check-wazuh-agent-connnection.py
/home/k-oguma/venv/lib/python3.6/site-packages/urllib3/connectionpool.py:986: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  InsecureRequestWarning,
(venv) [k-oguma@ip-172-30-0-100 ~]$ echo $?
0
```

### Abnormal (e.g. Disconnected)

```sh
(venv) [k-oguma@ip-172-30-0-100 ~]$ ./check-wazuh-agent-connnection.py -i
Traceback (most recent call last):
  File "./check-wazuh-agent-connnection.py", line 191, in <module>
    main()
  File "./check-wazuh-agent-connnection.py", line 162, in main
    raise ConnectionError(alert_box)
ConnectionError: [{'status': 'Disconnected', 'name': 'linux-agent_for_docker', 'wazuh_id': '005'}]
(venv) [k-oguma@ip-172-30-0-100 ~]$ echo $?
1
```
