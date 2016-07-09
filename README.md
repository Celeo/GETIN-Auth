# GETIN-HR

GETIN-HR is a web application for keeping track of applicants and members for an EVE alliance. It was made for the GETIN alliance.

## Installing

Download from my Git server, install the Python prerequisites, and copy and edit the configuration:

```bash
$ git clone https://git.celeodor.com/Celeo/GETIN-HR.git
$ cd GETIN-HR
$ virtualenv env
$ . env/bin/activate
$ pip install -r requirements.txt
$ cp hr/config.cfg.example hr/config.cfg
```

Edit `hr/config.cfg`, supplying the access string to your database (SQLite works fine) and your EVE third party app information.

```bash
$ ./gunicorn_run.sh
```
