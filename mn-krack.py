#!/usr/bin/python

"""This code tests if APs are affected by CVE-2017-13082 (KRACK attack) and
determine whether an implementation is vulnerable to attacks."""

__author__ = "Ramon Fontes"
__credits__ = ["https://github.com/vanhoefm/krackattacks-test-ap-ft"]

from time import sleep

from mininet.log import setLogLevel, info
from mininet.term import makeTerm
from mn_wifi.net import MininetWithControlWNet, Mininet_wifi
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference


def topology():

    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Creating nodes\n")
    sta1 = net.addStation('sta1', ip='10.0.0.1/8', position='50,0,0',
                          encrypt='wpa2')
    ap1 = net.addStation('ap1', mac='02:00:00:00:01:00',
                         ip='10.0.0.101/8', position='10,30,0')
    ap2 = net.addStation('ap2', mac='02:00:00:00:02:00',
                         ip='10.0.0.102/8', position='100,30,0')

    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=3.5)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    ap1.setMasterMode(intf='ap1-wlan0', ssid='handover', channel='1',
                      ieee80211r=True, mobility_domain='a1b2',
                      passwd='123456789a', encrypt='wpa2')
    ap2.setMasterMode(intf='ap2-wlan0', ssid='handover', channel='6',
                      ieee80211r=True, mobility_domain='a1b2',
                      passwd='123456789a', encrypt='wpa2')

    info("*** Plotting Graph\n")
    net.plotGraph(min_x=-100, min_y=-100, max_x=200, max_y=200)

    info("*** Starting network\n")
    net.build()

    sta1.cmd("iw dev sta1-wlan0 interface add mon0 type monitor")
    sta1.cmd("ifconfig mon0 up")

    sleep(10)
    # We need AP scanning. Otherwise, roam won't wok
    # This terminal automatically closes after 10 seg.
    makeTerm(sta1, title='Scanning', cmd="bash -c 'echo \"AP Scanning\" && iw dev sta1-wlan0 scan;'")
    # Run the FT test
    makeTerm(sta1, title='KrackAttack', cmd="bash -c 'cd krackattack && python krack-ft-test.py;'")

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
