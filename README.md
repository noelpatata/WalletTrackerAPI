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
pip install -r requirements.txt
```

---

## Environment Preparation
### Generate keys
In order to encrypt the tokens with asymetric cryptography, you need to generate the keys.
``` bash
python generateKeys.pem
```
### Setup env variables
The config.py defines the variables regarding secrets. We need to create them.

Windows:

``` cmd
setx DB_HOST 127.0.0.1
setx DB_USER myuser
setx DB_PASSWORD mypassword
setx DB_NAME mydb
```
Linux:

``` bash
export DB_HOST=127.0.0.1
export DB_USER=myuser
export DB_PASSWORD=mypassword
export DB_NAME=mydb
```
---

## Development
### Serve web
Linux:

``` bash
uwsgi --http [ip address]:[port] --master -p [thread number] -w [python file name (without .py extension)]:app
```
Windows:

``` cmd
waitress-serve --host 127.0.0.1 hello:app
```
## Mysql Setup
### Pull docker image

``` bash
docker pull mysql:8.0
```
### Create docker container

``` bash
docker run -d \
  --name my_mysql \
  -e MYSQL_ROOT_PASSWORD=rootpassword \
  -e MYSQL_DATABASE=mydb \
  -e MYSQL_USER=myuser \
  -e MYSQL_PASSWORD=mypassword \
  -p 3306:3306 \
  mysql:8.0
```
### Mysql Database Script
``` mysql
CREATE DATABASE WalletTracker;
USE WalletTracker;
CREATE TABLE User (
  id BIGINT NOT NULL AUTO_INCREMENT,
  username VARCHAR(45) NOT NULL,
  password LONGTEXT NULL,
  salt LONGTEXT NULL,
  private_key LONGTEXT NULL,
  public_key LONGTEXT NULL,
  client_public_key LONGTEXT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX username_UNIQUE (username ASC) VISIBLE
);
  
CREATE TABLE ExpenseCategory (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name TEXT NOT NULL,
    user BIGINT,
    sortOrder INT NULL,
    FOREIGN KEY (user) REFERENCES User(id) ON DELETE CASCADE
);

CREATE TABLE Expense (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    price DOUBLE,
    expenseDate DATE,
    category BIGINT,
    user BIGINT,
    FOREIGN KEY (user) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (category) REFERENCES ExpenseCategory(id) ON DELETE CASCADE
);
```
---

