#!/bin/bash
export PYTHONPATH=.; rm midnav2.db; rm -rf alembic/versions/*; alembic revision --autogenerate -m "initial"; ./prestart.sh
