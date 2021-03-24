# rtViz

Simple real time data visualization scripts in python. 

These scripts read CSVs from standard in and plot the data. Run test_*.py to run the each script with randomly generated data.

**rate_plot** -- plots multiple timeseries on the same line. The input data should be a CSV, with lines of the form : ```timestamp, y_value 1, y_value 2, ..., y_value n```. Set the number of y variables and their names in the script.

**topo_plot** -- plots a 4 node topology graph with edge-widths proportional to flow rate. Expects CSV input with lines of the form: ```timestamp, client_to_switch rate, attacker_to_switch rate, client_to_server rate, attacker_to_server rate```


### todo

*where does the data come from?* 

Two options: 

- measure from endpoints (attack client, drone client, server), send to common point
- measure from onos

In either case, the question is how to discriminate from drone vs attack traffic.

