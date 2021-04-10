#final run defense

# python3 pcap_tools.py --cmd id_drones --pcap pcaps/cap_node2_after2_20210408_195339.pcap --drone "10.250"
# output: 
# 10.250.223.221 : 104
# 10.250.223.219 : 52
# 10.250.223.216 : 104
# 10.250.223.217 : 52
# 10.250.223.215 : 0


python3 pcap_viz.py --pcap pcaps/cap_node2_after2_20210408_195339.pcap --node1_pcap pcaps/cap_node1_after2_20210408_195339.pcap  --attacker 10.64.5.130 --drones 10.250.223.221 10.250.223.219 10.250.223.216 10.250.223.217 10.250.223.215 --defense_run
