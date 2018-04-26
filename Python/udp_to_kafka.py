# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

### Imports ###
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt
from struct import *

import pickle
from elasticsearch import Elasticsearch, helpers
from IPy import IP

# Parsing functions
from parser_modules import mac_address, icmp_parse, ip_parse, netflowv9_parse, int_parse, ports_and_protocols, \
    name_lookups

# Field types, defined ports, etc
from field_types import v9_fields
from netflow_options import *
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import json

### Get the command line arguments ###
try:
    arguments = getopt.getopt(sys.argv[1:], "hl:", ["--help", "log="])

    for option_set in arguments:
        for opt, arg in option_set:

            if opt in ('-l', '--log'):  # Log level
                arg = arg.upper()  # Uppercase for matching and logging.basicConfig() format
                if arg in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]:
                    log_level = arg  # Use what was passed in arguments

            elif opt in ('-h', '--help'):  # Help file
                with open("./help.txt") as help_file:
                    print(help_file.read())
                sys.exit()

            else:  # No options
                pass

except Exception:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.")

### Logging Level ###
# Per https://docs.python.org/2/howto/logging.html
try:
    log_level  # Check if log level was passed in from command arguments
except NameError:
    log_level = "WARNING"  # Use default logging level

logging.basicConfig(level=str(log_level))  # Set the logging level
logging.warning('Log level set to ' + str(log_level) + " - OK")  # Show the logging level for debug

### DNS Lookups ###
#
# Reverse lookups
try:
    if dns is False:
        logging.warning("DNS reverse lookups disabled - DISABLED")
    elif dns is True:
        logging.warning("DNS reverse lookups enabled - OK")
    else:
        logging.warning("DNS enable option incorrectly set - DISABLING")
        dns = False
except:
    logging.warning("DNS enable option not set - DISABLING")
    dns = False

# RFC-1918 reverse lookups
try:
    if lookup_internal is False:
        logging.warning("DNS local IP reverse lookups disabled - DISABLED")
    elif lookup_internal is True:
        logging.warning("DNS local IP reverse lookups enabled - OK")
    else:
        logging.warning("DNS local IP reverse lookups incorrectly set - DISABLING")
        lookup_internal = False
except:
    logging.warning("DNS local IP reverse lookups not set - DISABLING")
    lookup_internal = False

# Check if the Netflow v9 port is specified
try:
    netflow_v9_port
except NameError:  # Not specified, use default
    netflow_v9_port = 9995
    logging.warning("Netflow v9 port not set in netflow_options.py, defaulting to " + str(netflow_v9_port) + " - OK")

# Set up socket listener
try:
    netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    netflow_sock.bind(('0.0.0.0', netflow_v9_port))
    logging.warning("Bound to port " + str(netflow_v9_port) + " - OK")
except ValueError as socket_error:
    logging.critical("Could not open or bind a socket on port " + str(netflow_v9_port) + " - FAIL")
    logging.critical(str(socket_error))
    sys.exit()

# Spin up ES instance
es = Elasticsearch([elasticsearch_host])

# Stage individual flow
global flow_index
flow_index = {}
flow_index["_source"] = {}

# Stage multiple flows for the bulk Elasticsearch API index operation
global flow_dic
flow_dic = []

# Cache the Netflow v9 templates in received order to decode the data flows. ORDER MATTERS FOR TEMPLATES.
global template_list
template_list = {}

# Record counter for Elasticsearch bulk API upload trigger
record_num = 0

### Netflow v9 Collector ###
if __name__ == "__main__":

    icmp_parser = icmp_parse()  # ICMP Types and Codes
    ip_parser = ip_parse()  # Unpacking and parsing IPv4 and IPv6 addresses
    mac = mac_address()  # Unpacking and parsing MAC addresses and OUIs
    netflow_v9_parser = netflowv9_parse()  # Parsing Netflow v9 structures
    int_un = int_parse()  # Unpacking and parsing integers
    ports_protocols_parser = ports_and_protocols()  # Ports and Protocols
    name_lookups = name_lookups()  # DNS reverse lookups

    # Continually collect packets
    producer = KafkaProducer(
        #value_serializer=lambda m: pickle.dumps(m).encode('utf-8'),
        bootstrap_servers=['localhost:9092'],
        send_buffer_bytes=131072
    )
    while True:

        pointer = 0  # Tracking location in the packet
        flow_counter = 0  # For debug purposes only

        flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)  # Listen for packets inbound

        #print "No of records {}".format(record_num)


        future = producer.send('ipfix-udp',flow_packet_contents)
