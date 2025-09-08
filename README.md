# Wallet Tracker Rest API
## Installation
``` bash
git clone https://github.com/noelpatata/WalletTrackerAPI.git && cd WalletTrackerAPI/
```

## Python's virtual environment
### Create

``` bash
python3 -m venv env
```
### Activate 
Linux:

``` bash
sudo apt install -y default-libmysqlclient-dev pkg-config build-essential
sudo apt install -y python3.12-dev
source env/bin/activate
```
Windows:

``` cmd
.\env\Scripts\Activate.ps1
```
### Install dependencies

``` bash
sudo apt install -y pkg-config default-libmysqlclient-dev build-essential
```

``` bash
pip install -r requirements.txt
```

---

## Environment Preparation
### Generate keys
In order to encrypt the tokens with asymetric cryptography, you need to generate the keys.
``` bash
python generateKeys.pem
```
---

## Development
### Serve web
Linux:

``` bash
uwsgi --http [ip address]:[port] --master -p [thread number] -w app:app
```
Windows:

``` cmd
waitress-serve --host 127.0.0.1 app:app
```
## Mysql Setup
### Pull docker image

``` bash
docker pull mysql:8.0
```
### Create docker container

``` bash
docker build -t wallet_tracker_mysql . \
docker run -d  --name mysql -e MYSQL_ROOT_PASSWORD=adminadmin -e MYSQL_DATABASE=wallet_tracker -e MYSQL_USER=noel -e MYSQL_PASSWORD=adminadmin -p 3306:3306  wallet_tracker_mysql \
docker start wallet_tracker_mysql
```
---

