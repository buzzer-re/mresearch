import argparse
import re
import pefile
import os, sys
import subprocess
import collections

import networkx
from networkx.drawing.nx_agraph import write_dot
from networkx.algorithms import bipartite


def extract_hostnames(hostname, regex_rule, valid_domains):
	possible_hosts = regex_rule.findall(hostname)
	
	possible_hosts = list(filter(
		lambda possible_host: possible_host.split(".")[-1].lower() in valid_domains,
		possible_hosts
	))
	return possible_hosts

if __name__ == '__main__':
	args  = argparse.ArgumentParser("Visualized shared hostname between a directory of malware samples")
	args.add_argument("--malwares_path", help="Directory with malware samples", required=True)
	args = args.parse_args()
 	 
	DOMAIN_FILES = 'domain_suffixes.txt'

	if not os.path.exists(DOMAIN_FILES):
		print("{} not found!".format(DOMAIN_FILES))
		sys.exit(1)
	
	valid_domains = []

	# Create an set of domains suffixes and then create a dictionary for quick access
	with open(DOMAIN_FILES, "r") as domain:
		valid_domains = map( lambda domain_prefix: domain_prefix.rstrip(), domain) 
		valid_domains = {valid_domain:None for valid_domain in valid_domains}
	
	network = networkx.Graph() # Start our Graph	
	malware_path = args.target_path

	# This rule validate an domain format string, but can have false positives such as USER32.dll
	rule = r'(?:[a-zA-Z0-9](?:[a-zA-z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'
	compiled_rule = re.compile(rule)
	path_tree = os.walk(malware_path)
	
	for root, dirs, files in path_tree:
		for path in files:
			abs_dir = os.path.join(root,path)	
			try:
				pefile.PE(abs_dir)
			except pefile.PEFormatError:
				continue
			
			# Yep, i'm using strings here
			strs = subprocess.check_output(["strings", abs_dir]).decode()
			hosts = extract_hostnames(strs, compiled_rule, valid_domains)
			
			if len(hosts) > 0:
				# Build graph
				network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0)
				for hostname in hosts:
					network.add_node(hostname, label=hostname, color='blue', penwidth=10, bipartite=1)
					network.add_edge(hostname, path)
	
	
	write_dot(network, 'domain_network.dot')

