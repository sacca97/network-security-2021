#!/bin/bash

xfce4-terminal -e 'bash -c "./ap/ap; bash"' -T "AP"

xfce4-terminal -e 'bash -c "./mitm/mitm; bash"' -T "MitM"

xfce4-terminal -e 'bash -c "./client/client; bash"' -T "Client"