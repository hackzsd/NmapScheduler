# Nmap Scheduler
A Simple Command line Python script to schedule multiple batches of nmap scans.

# Examples : 

python NmapScheduler.py -f iplist.txt -v
python  NmapScheduler.py --hostsfile iplist.txt --verbose

# About Config.json

Config.json file is a config file used by the scheduler to run nmap scans at desired time.

If config file is not present in current directory, the scheduler will run instanly  with default config and nmap commands.

