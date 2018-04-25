#!/bin/bash
gunicorn -w 3 -b 127.0.0.1:17424 auth:app -t 60
