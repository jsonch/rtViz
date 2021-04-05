#runtest.sh

python3 pcap_viz.py --pcap cap_node2_before_with_attack_20210325_T1416PT.pcap --drones 10.250.254.96 10.250.254.99 10.250.254.101 10.250.254.103 10.250.254.105 --attacker 10.64.5.130 --node1_pcap cap_node1_before_with_attack_20210325_T1416PT.pcap $1
