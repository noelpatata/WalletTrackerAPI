# Wallet Tracker Rest API
## Installation
### Linux:
``` bash
git clone https://github.com/noelpatata/WalletTrackerAPI.git && cd WalletTrackerAPI/
```

``` bash
python3.8 -m venv env
```

``` bash
pip install -r requirements.txt
```
---

## Preparation
In order to encrypt the tokens with asymetric cryptography, you need to generate the keys.
``` bash
python generateKeys.pem
```

### Mysql Database Script
``` mysql
create database WalletTracker;
use WalletTracker;
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
    FOREIGN KEY (category) REFERENCES ExpenseCategory(id) ON DELETE CASCADE
);
```
---
## Deployment
``` bash
uwsgi --http [ip address]:[port] --master -p [thread number] -w [python file name (without .py extension)]:app
```
