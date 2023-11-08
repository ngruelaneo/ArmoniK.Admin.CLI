FROM python:3.9-slim

WORKDIR /src

COPY . .

RUN apt-get update && \
    apt-get install -y git && \
    pip install build && \
    python -m build && \
    pip install dist/*.whl

CMD [ "python", "src/armonik_cli/admin.py" ]

# LAUNCHING CLI IN DOCKER

# CREATE IMAGE
# docker build -t test_cli:latest .

# RUN AND GET INSIDE THE DOCKER 
# docker run -it -p 5001:5001 test_cli bash

#python src/armonik_cli/admin.py  --endpoint 172.17.193.68:5001 list-session --running