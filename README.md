# Wallet Tracker Rest API
## Installation
``` bash
git clone https://github.com/noelpatata/WalletTrackerAPI.git && cd WalletTrackerAPI/
```

``` bash
python3 -m venv env
```

### Activate
Linux
``` bash
sudo apt install -y default-libmysqlclient-dev pkg-config build-essential
sudo apt install -y python3.12-dev
source env/bin/activate
```
Windows
``` cmd
.\env\Scripts\activate
```
### Install dependencies
``` bash
pip install -r requirements.txt
```

---

## Preparation
In order to encrypt the tokens with asymetric cryptography, you need to generate the keys.
``` bash
python generateKeys.pem
```

---

## Deployment
### Linux
``` bash
uwsgi --http [ip address]:[port] --master -p [thread number] -w [python file name (without .py extension)]:app
```
### Windows
``` cmd
waitress-serve --host 127.0.0.1 hello:app
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
  PRIMARY KEY (id),
  UNIQUE INDEX username_UNIQUE (username ASC) VISIBLE
);
  
CREATE TABLE ExpenseCategory (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name TEXT NOT NULL,
    user BIGINT,
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

