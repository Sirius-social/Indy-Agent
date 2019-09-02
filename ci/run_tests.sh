#!/bin/bash
cd /app
pytest
python manage.py test --noinput
