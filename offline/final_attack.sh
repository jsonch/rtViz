#final run attack

# python3 pcap_tools.py --cmd id_drones --pcap pcaps/cap_node2_before3_20210408_184857.pcap --drone "10.250"
# output: 
# 10.250.224.85 : 52
# 10.250.224.83 : 52
# 10.250.224.86 : 156
# 10.250.224.87 : 52
# 10.250.224.84 : 0


python3 pcap_viz.py --pcap pcaps/cap_node2_before3_20210408_184857.pcap --node1_pcap pcaps/cap_node1_before3_20210408_184856.pcap  --attacker 10.64.5.130 --drones 10.250.224.83 10.250.224.84 10.250.224.85 10.250.224.86 10.250.224.87
