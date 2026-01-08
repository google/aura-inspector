# aura-inspector

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).


## Introduction

<b>aura-inspector</b> is a Swiss Army knife of Salesforce Experience Cloud testing. It facilitates in discovering misconfigured Salesforce Experience Cloud applications as well as automates much of the testing process. Some of it's functionality includes:
- Discovery of accessible records from both Guest and Authenticated contexts
- Ability to get the total number of records of objects using undocumented GraphQL Aura method
- Checks for self-registration capabilities
- Facilitates in discovery of Record List components, providing UI access to list of misconfigured objects
- Discovery of "Home URLs", which could allow unauthorized access to sensitive administrative functionality

## Installation

### pipx (Recommended)

The tool can be installed with pipx using the command below.
```
pipx install git+<URL>
```

### pip

The tool requires Python 3 to run and pip to download the dependencies. We recommend creating a virtual environment to install the dependencies.
```
git clone <URL>
cd aura-inspector
virtualenv env
source ./env/bin/activate
pip3 install -r requirements.txt
```

## Getting Started
The help menu can be invoked using the <b>-h</b> flag, which provides a list of configurations.

```
python3 aura_cli.py -h
usage: python3 aura_cli.py [-h] [-u URL] [-c COOKIES] [-o OUTPUT_DIR] [-l OBJECT_LIST] [-d] [-v] [-p PROXY] [-k] [-a] [--app APP] [--aura AURA] [--context CONTEXT] [--token TOKEN] [--no-gql] [-r AURA_REQUEST_FILE]

options:
  -h, --help            show this help message and exit
  -u, --url URL         Root URL of Salesforce application to audit
  -c, --cookies COOKIES
                        Cookies after authenticating to Salesforce application
  -o, --output-dir OUTPUT_DIR
                        Output directory
  -l, --object-list OBJECT_LIST
                        Pull records only the provided objects. Comma separated list of objects.
  -d, --debug           Print debug information
  -v, --verbose         Print verbose information
  -p, --proxy PROXY     Proxy requests
  -k, --insecure        Ignore invalid TLS certificates
  --app APP             Provide the target salesforce app's path (e.g: /myApp), the script will try to detect it if not provided
  --aura AURA           Provide the target salesforce aura's path (e.g: /aura), the script will try to detect it if not provided
  --context CONTEXT     Provide a context to be used as aura.context in POST requests, the script will use a dummy one if not provided
  --token TOKEN         Provide an aura token to be used as aura.token in POST requests, the script will use a dummy one if not provided
  --no-gql              Do not check for GraphQL capability and do not use it
  --no-banner           Do not display banner
  -r, --aura-request-file AURA_REQUEST_FILE
                        Provide a request file to an /aura endpoint
```

The tool offers a variety of options that can be useful in different scenarios. The following cover a few different situations.

## Basic Usage

Using the tool in the standard configuration is as simple as running the following command. This will run all checks in an unauthenticated manner and return what is accessible from a Guest user perspective.

`python3 aura_cli.py -u <URL>`

The output will also reveal whether there is a self-registration functionality you can use to create an account. If you do have the opportunity to signup on the instance, running the tool from an authenticated context will likely yield more results. 

To run the tool in an authenticated context, either supply the SID cookie using the <b>-c</b> parameter or let the tool parse this and other parameters for you by supplying a file with the contents of an arbitrary request to the aura endpoint in an authenticated session. 

`python3 aura_cli.py -r <AURA_REQUEST_FILE>`

## Handling Multiple Apps

A single instance could have multiple custom apps hosted on it. This could typically be identified if you see something along the lines of `/<custom-app-name>/s` in the path. If this is the case, we recommend finding all apps, and specifying them using the `--app` parameter, as the output could differ significantly. It's also advised to try run the tool against the default app "/" if there are any custom apps hosted on the instance.

# Developed By:
- Amine Ismail
- Anirudha Kanodia
