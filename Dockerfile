FROM python:3.6-alpine as base

FROM base as builder
RUN mkdir /install
WORKDIR /install

COPY requirements.txt /requirements.txt
RUN pip install --install-option="--prefix=/install" -r /requirements.txt

FROM base
# install libmagic (for python-magic module)
RUN mkdir /selectel && apk add libmagic
# copy other dependencies
COPY --from=builder /install /usr/local
# copy the script
COPY loader.py /selectel/loader.py
# work in the folder with the shared files
WORKDIR /selectel/shared

ARG LOGIN=""
ARG PASSWORD=""
ARG STORAGE=""

ENV LOGIN=$LOGIN
ENV PASSWORD=$PASSWORD
ENV STORAGE=$STORAGE

ENTRYPOINT ["python", "/selectel/loader.py"]