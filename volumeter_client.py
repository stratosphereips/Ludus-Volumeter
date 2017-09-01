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

import argparse
import socket
import json

class Volumeter_client(object):
	"""	Simple client for controling Volumeter
		COMMANDS:
			'GET_DATA'				- get json
			'RESET'					- reset counters
			'GET_DATA_AND_RESET'	- return data and reset the counters afterwards
	"""
	def __init__(self, host='localhost', port=53333):
		#create socket
		self.host = host
		self.port =port

	def get_data(self):
		self.socket = socket.socket()
		self.socket.connect((self.host,self.port))
		self.socket.sendall('GET_DATA')
		data = self.socket.recv(1024)
		#print len(data)
		print data
		self.socket.close()
		return data

	def reset_counter(self):
		self.socket = socket.socket()
		self.socket.connect((self.host,self.port))
		self.socket.sendall("RESET")
		ret = self.socket.recv(1024)
		self.socket.close()
		return ret

	def get_data_and_reset(self):
		self.socket = socket.socket()
		self.socket.connect((self.host,self.port))
		self.socket.sendall("GET_DATA_AND_RESET")
		ret = self.socket.recv(1024)
		self.socket.close()
		return ret

		
if __name__ == '__main__':
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--command', help='Command to be send to the volumeter', action='store', required=True, type=str)
	parser.add_argument('-p', '--port', help='Port used for communication with Ludus.py', action='store', required=False, type=int, default=53333)
	args = parser.parse_args()


	s = socket.socket()	# Create a socket object
	host = 'localhost'	# Get local machine name
	port = 53333		# Reserve a port for your service.

	s.connect((host, args.port))
	s.sendall(args.command)
	print s.recv(1024)
	s.close()
