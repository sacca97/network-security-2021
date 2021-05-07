#!/bin/bash

DEBUG=1

if [[ $DEBUG -eq 1 ]]
then
    make build
fi

if ! command -v xfce4-terminal &> /dev/null
then
    gnome-terminal --window -e 'bash -c "./ap/ap; bash"' \
    --window -e 'bash -c "./mitm/mitm; bash"' \
    --window -e 'bash -c "./client/client; bash"'
else
    xfce4-terminal --window -e 'bash -c "./ap/ap; bash"' -T "AP" \
    --window -e 'bash -c "./mitm/mitm; bash"' -T "MitM" \
    --window -e 'bash -c "./client/client; bash"' -T "Client"
fi