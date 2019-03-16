FROM python:2.7-stretch

RUN pip install --upgrade elasticsearch
RUN apt-get -y update && apt-get -y install xmlstarlet

ADD ingest /bin/
ADD VulntoES.py /opt/VulntoES/
WORKDIR /opt/VulntoES

ENTRYPOINT ["/bin/bash"]
