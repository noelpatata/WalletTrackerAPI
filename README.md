# Wallet Tracker Rest API for development environment
## Clone
``` bash
git clone https://github.com/noelpatata/WalletTrackerAPI.git && cd WalletTrackerAPI/
```

## Python's virtual environment
### Create

``` bash
python3 -m venv .venv
```
### Activate 
Linux:

``` bash
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

## Deployment

``` bash
docker compose up -d --build
```

## Run tests

Make sure you have the virtual environment activated.
``` bash
pytest -v
```

---

