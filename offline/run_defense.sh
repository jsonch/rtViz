#runtest.sh

python3 pcap_viz.py --pcap cap_node2_after_with_attack_20210325_T1455PT.pcap --drones 10.250.253.248 10.250.253.249 10.250.253.250 10.250.253.251 10.250.253.252 --attacker 10.64.5.130 --node1_pcap cap_node1_before_with_attack_20210325_T1416PT.pcap $1