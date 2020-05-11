import networkx
from networkx.drawing.nx_agraph import  write_dot
from networkx.algorithms import bipartite
import pefile
import sys, os

import argparse

import hashlib



if __name__ == '__main__':
	args = argparse.ArgumentParser(description="Transform malwares resources into an graph")
	args.add_argument("--target-path", help="malware samples folder", required=True)
	args = args.parse_args()
		
	malwares_path = args.target_path

	if not os.path.exists(malwares_path):
		print("Invalid directory")
		sys.exit(1)
	
	network = networkx.Graph()

	
	path_tree = os.walk(malwares_path)
	
	
	for root, dirs, files in path_tree:
		for path in files:
			pe = None
			sample_abspath = os.path.join(root,path)
			try:
				pe = pefile.PE(sample_abspath)
			except pefile.PEFormatError:
				continue

						
			if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
				network.add_node(path, label=path[:32], color='black', penwidth=5, bipartide=0)
				for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
					if resource_type.id != None and hasattr(resource_type, 'directory'):
						for resource_id in resource_type.directory.entries:
							for resources in resource_id.directory.entries:
								raw_data = hashlib.sha1(pe.get_data(resources.data.struct.OffsetToData, resources.data.struct.Size)).digest().hex()
								network.add_node(raw_data, label=raw_data, color='blue', penwidth=10, bipartide=1)	
								network.add_edge(path, raw_data)


	
	write_dot(network, 'resource_network.dot')
