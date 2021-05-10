#!/bin/bash

DEBUG=1

if [[ $DEBUG -eq 1 ]]
then
    make build
fi

if ! command -v xfce4-terminal &> /dev/null
then
    gnome-terminal -e 'bash -c "./ap/ap; bash"'
    gnome-terminal -e 'bash -c "./mitm/mitm; bash"'
    gnome-terminal -e 'bash -c "./client/client; bash"'
else
    xfce4-terminal -e 'bash -c "./ap/ap; bash"' -T "AP"
    xfce4-terminal -e 'bash -c "./mitm/mitm; bash"' -T "MitM"
    xfce4-terminal -e 'bash -c "./client/client; bash"' -T "Client"
fi