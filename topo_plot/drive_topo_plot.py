import time, sys, random 

# generates some test data for liveplot.py

def main():
    cli_to_switch = 0
    atk_to_switch = 0
    cli_to_server = 0
    atk_to_server = 0
    curtime = 0
    interval = .5
    for i in range(100):
        print ("%s, %s, %s, %s, %s\n" 
            % (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server)
            ,flush=True)
        curtime += interval
        cli_to_switch = random.randint(1, 2)
        atk_to_switch = random.randint(0, 20)
        atk_to_server = atk_to_switch
        if(atk_to_server > 10):
            cli_to_server = 0
        else:
            cli_to_server = cli_to_switch
        time.sleep(interval)
    return 0


if __name__ == '__main__':
    sys.exit(main())
