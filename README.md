# Self Sovereign Identity service for SIRIUS project
[https://socialsirius.com/](https://socialsirius.com/ "Site")


# Features
- Based on **Hyperledger** **Indy** project. [https://hyperledger-indy.readthedocs.io/en/latest/index.html](https://hyperledger-indy.readthedocs.io/en/latest/index.html)
- Indy **Agend** and **Hub** implementation. [https://hyperledger-indy.readthedocs.io/projects/agent/en/latest/README.html#agent-types](https://hyperledger-indy.readthedocs.io/projects/agent/en/latest/README.html#agent-types)
- Implement messaging protocol: [https://hyperledger-indy.readthedocs.io/projects/agent/en/latest/README.html#messaging-protocol](https://hyperledger-indy.readthedocs.io/projects/agent/en/latest/README.html#messaging-protocol)
- Implement ARIES-RFC features: [https://github.com/hyperledger/aries-rfcs/tree/master/features](https://github.com/hyperledger/aries-rfcs/tree/master/features)

# Dev env prerequirements
  
- Linux: set environment variable **VERSION** to **dev** (ex: ```export VERSION=dev```)
- Windows: set environment variable **VERSION** to **dev** (ex: ```SET VERSION=dev```)
- If you use **PyCharm IDE** mark **app** directory as source dir, then Configure Remote interpreter via docker-compose.yml file and set path mappings as: Local path = **<project_dir>/app**  Remote path = **/app**
- Run Django app in debug mode: ```python manage.py runserver 0.0.0.0:8888```

# Project structure
- **ci** directory: docker environment for development and testing
- **docker-compose.yml** files: Dev+Test environment for PyCharm IDE [https://www.jetbrains.com/help/pycharm/docker-compose.html](https://www.jetbrains.com/help/pycharm/docker-compose.html "Help")
- **app**:  Application sources and run scripts


# Architecture
TODO

# Deployment instructions

TODO
