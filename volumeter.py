#!/usr/bin/env python
#  Copyright (C) 2017  Sebastian Garcia, Ondrej Lukas
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Author:
# Ondrej Lukas      ondrej.lukas95@gmail.com    

# Description
# A program that analyzes output of conntrack and counts pkts and bytes transfered in each port in each protocol
import subprocess
import re
import datetime
import json
import argparse
import sys
import socket
import os
import multiprocessing
from multiprocessing import Queue

def default(o):
    return o._asdict()

class MyEncoder(json.JSONEncoder):
    """Simple JSON encoder for storing Port objects"""
    def default(self, obj):
        if not isinstance(obj, Port):
            return super(MyEncoder, self).default(obj)
        return obj.__dict__
class Port(object):
    """Container for volumes counting. For unfinished conections, buffers (1 pkts/event) are used as an estimation. THIS ESTIMATE IS ONLY USED IF ASKED FOR THE VOLUME BEFORE THE CONNNECTION ENDS. Upon
    recieving [DESTORY] event for the connection, value in buffer is reseted (we don't need it anymore because we ahave the real value)"""
    def __init__(self,port_number):
        self.id = port_number
        self.bytes = 0
        self.packets = 0
        self.buffer = 0
    
    def add_values(self,new_packets, new_bytes, timestamp):
        """Process destroyed connection, clear buffers"""
        #update values
        self.packets += new_packets
        self.bytes += new_bytes
        print "[{}] New connection destroyed in port {} \tPKTS: {}, BYTES: {}".format(timestamp, self.id, self.packets,self.bytes)
        #erase buffer
        self.tcp_buffer = 0


    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

    def increase_buffer(self, timestamp):
        """Connection  is still active, estimate it with 1 pkt in buffer"""
        print "[{}] Active connection in port {} - buffer incremented".format(timestamp, self.id)
        self.buffer +=1

class Counter(multiprocessing.Process):
    """Counts pkts/bytes in each port"""
    def __init__(self, queue, router_ip, port):
        multiprocessing.Process.__init__(self)
        self.queue = queue
        self.tcp = {}
        self.icmp = Port('icmp')
        self.udp = {}

        self.router_ip = router_ip
        self.socket =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.socket.bind(('localhost', port))
        self.socket.listen(5)

    def process_event(self,string):
        """Parses the events from conntrack and stores the volumes (pkts, bytes). Port class is used as a container"""
        parts = []
        #get the timestamp
        split = string.split("\t")
        timestamp = split[0].strip("[]")
        #parse the rest of the line
        for part in split[1].split(' '):
            if len(part) > 0:
                parts.append(part.strip())
        #get the basic information about the connection
        event = parts[0].strip("[]")
        protocol = parts[1]

        #is it a protocol with ports?
        if protocol == "udp" or protocol == "tcp":
           
            #has the connection finished yet?
            if event.lower() == 'destroy':
                src_ip = parts[3].strip("src=")
                dst_ip = parts[4].strip("dst=")
                sport = parts[5].strip("sport=")
                dport = parts[6].strip("dport=")
                #[UNREPLIED] event
                if parts[9].strip("[]").lower() == "unreplied":
                    pkts = int(parts[7].strip("packtets="))
                    data_bytes = int(parts[8].strip("bytes="))
                else:
                    pkts = int(parts[7].strip("packtets=")) +  int(parts[13].strip("packtets="))
                    data_bytes = int(parts[8].strip("bytes=")) + int(parts[14].strip("bytes="))
                #store the vlaues in the dict
                if dst_ip == ROUTER_PUBLIC_IP:
                    try:
                        self.udp[dport].add_values(protocol, pkts, data_bytes,timestamp)
                    except KeyError:
                        #first time we see it
                        self.udp[dport] = Port(dport)
                        self.udp[dport].add_values(protocol, pkts, data_bytes,timestamp)
            else: #Active connection - at least estimate the number of pkts
                if protocol == 'tcp':
                    dst_ip = parts[6].strip("dst=")
                    dport = parts[8].strip("dport=")
                else:
                    dst_ip = parts[5].strip("dst=")
                    dport = parts[8].strip("dport=")
                #store values
                if dst_ip == ROUTER_PUBLIC_IP:
                    try:
                        self.tcp[dport].increase_buffer(protocol,timestamp)
                    except KeyError:
                        #first time we see it
                        self.tcp[dport] = Port(dport)
                        self.tcp[dport].increase_buffer(protocol,timestamp)
        #ICMP
        elif protocol == "icmp":
            dst_ip = parts[4].strip("dst=")
            if dst_ip == ROUTER_PUBLIC_IP:
                if event.lower() == 'destroy':
                    self.icmp.add_values(int(parts[8].strip("packtets=")) +  int(parts[15].strip("packtets=")), int(parts[8].strip("packtets=")) +  int(parts[15].strip("packtets=")),timestamp)
                else:
                    self.icmp.increase_buffer(timestamp)
        else:
            #we are not interested in anyhting else for now, just continue
            pass


    def process_msg(self, msg):
        """Processes the message recieved from the control program and if it contains known commnad, generates the respons"""
        if msg.lower() == 'get_data':
            values = {'icmp':self.icmp, 'tmp':self.tcp, 'udp':self.udp}
            data = json.dumps(values, default=lambda x: x.__dict__)
            return data
        elif msg.lower() == 'get_data_and_reset':
            #get data first
            response = json.dumps(self.ports.values(), default=lambda x: x.__dict__)
            #reset counters
            self.reseted_counters()
            return response
        elif msg.lower() == 'reset':
            #reset counters
            self.icmp = Port('icmp')
            self.udp = {}
            self.tcp = {}
            #confirm
            return "reset_done"
        else: #we dont recognize the command
            return "unknown_command"

    def run(self):
        try:
            while True:
                #do we have a connection?
                try:
                    c, addr = self.socket.accept()
                    msg = c.recv(1024)
                    if msg:
                        response = self.process_msg(msg)
                        print "MSG: '{}'".format(msg)
                        c.send(response)
                        c.close()
                except socket.error:
                    #no, just wait
                    pass
                #read from the queue
                if not self.queue.empty():
                    line = self.queue.get()
                    if len(line) > 0:
                        self.process_event(line)
                        print "*{}\t{}".format(datetime.datetime.now(), line)
        except KeyboardInterrupt:
            self.socket.close()
            sys.exit()
        finally:
            self.socket.close()

if __name__ == '__main__':
    #get parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help='public address of the router', action='store', required=False, type=str, default='147.32.83.179')
    parser.add_argument('-p', '--port', help='Port used for communication with Ludus.py', action='store', required=False, type=int, default=53336)
    args = parser.parse_args()
    
    ROUTER_PUBLIC_IP = args.address
    PORT = args.port

    #create queue for comunication between processes
    queue = Queue()
    #create new process
    counter = Counter(queue, ROUTER_PUBLIC_IP, PORT)
    #start it
    counter.start()
    #yet another process
    process = subprocess.Popen('conntrack -E -o timestamp', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    #***MAIN LOOP***
    try:
        for line in process.stdout.readline().split('\n'):
            print line
            queue.put(line)
    except KeyboardInterrupt:
        print "\nInterrupting..."
        counter.join()
        print "Done"