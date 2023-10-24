import sys

with open(sys.argv[1], 'r') as f:
    lines = f.readlines()
data_dict = {"status": [], "start": [], "end": []}
successes = 0;
min_time = int(lines[1].strip().split(',')[1])
for line in lines[1:]:
    line = line.strip().split(',')
    status = int(line[0])
    if status == 0:
        successes += 1
    data_dict["status"].append(status)
    start_time = (int(line[1]) - min_time) / 1000000000.0
    end_time = (int(line[2]) - min_time) / 1000000000.0
    data_dict["start"].append(start_time)
    data_dict["end"].append(end_time)
client_duration = max(data_dict["end"]) - min(data_dict["start"])
tps = successes / client_duration
print(tps)
