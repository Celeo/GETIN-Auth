# GETIN-Auth

GETIN-Auth is a collection of web applications for the GETIN alliance.

## Installing

Download, install the Python prerequisites, and copy and edit the configuration:

```bash
$ git clone https://git.celeodor.com/Celeo/GETIN-Auth.git
$ cd GETIN-Auth
$ virtualenv env
$ . env/bin/activate
$ pip install -r requirements.txt
$ cp auth/config.cfg.example auth/config.cfg
```

Edit `auth/config.cfg`, supplying the access string to your database (SQLite works fine) and your EVE third party app information.

```bash
$ ./gunicorn_run.sh
```
