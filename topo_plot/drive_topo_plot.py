import time, sys, random 

# generates some test data to drive the topology plot

interval_dur = .2

num_baseline_intervals = 20
num_attack_intervals = 40

curtime = 0
def main():
    gen_baseline(num_baseline_intervals)
    gen_attack(num_attack_intervals)
    gen_baseline(num_baseline_intervals)


def gen_baseline(num_intervals):
    global curtime, interval_dur
    for i in range(num_intervals):
        cli_to_switch = random.randint(1, 2)
        atk_to_switch = 0
        cli_to_server = cli_to_switch
        atk_to_server = 0
        print ("%s, %s, %s, %s, %s\n" 
            % (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server)
            ,flush=True)
        time.sleep(interval_dur)
        curtime += interval_dur

def gen_attack(num_intervals):
    global curtime, interval_dur
    for i in range(num_intervals):
        cli_to_switch = random.randint(1, 2)
        atk_to_switch = random.randint(5, 10)
        cli_to_server = 0
        atk_to_server = atk_to_switch
        print ("%s, %s, %s, %s, %s\n" 
            % (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server)
            ,flush=True)
        time.sleep(interval_dur)
        curtime += interval_dur



if __name__ == '__main__':
    sys.exit(main())
