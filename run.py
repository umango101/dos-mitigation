from datetime import datetime
import itertools
import json
from pprint import pprint
import os
import shutil
import subprocess
import sys

session = sys.argv[1]
if len(sys.argv) > 2:
  skip_n = int(sys.argv[2])
else:
  skip_n = 0

code_dir = "/usr/local/dos-mitigation"
tmp_log_path = "/tmp/ansible.log"

print("Generating Inventory")
subprocess.run(["./inventory_gen.sh"])

log_dir = "{}/logs/{}".format(code_dir, session)

if os.path.exists(log_dir):
  action = input("Session with name '" + str(session) + "' already exists\n" + 
                  "(E)xit / (o)verwrite / (i)ncrement / (c)ontinue\n"
  )
  action = action.strip().lower()
  if action in ['o', 'overwrite']:
    shutil.rmtree(log_dir, ignore_errors=True)
    os.makedirs(log_dir)
  elif action in ['i', 'increment']:
    i=0
    while os.path.exists(log_dir + "_" + str(i)):
      i += 1
    log_dir = log_dir + "_" + str(i)
    session = session + "_" + str(i)
    os.makedirs(log_dir)
  elif action in ['c', 'continue']:
    existing = os.listdir(log_dir)
    skip_n = len([i for i in existing if not i.startswith('.')])
  else:
    print('Exiting')
    sys.exit()
else:
  action = "new"
  os.makedirs(log_dir)

param_file = "{}/.parameters.json".format(log_dir)
if action not in ['c', 'continue']:
  shutil.copyfile("{}/parameters.json".format(code_dir), param_file)
with open(param_file) as f:
  params = json.load(f)

keys, values = zip(*params.items())
permutations = [dict(zip(keys, v)) for v in itertools.product(*values)]

for p in permutations:
  attack_type = p['attack_mitigation_pair'][0]
  mitigation = p['attack_mitigation_pair'][1]
  p['attack_type'] = attack_type
  
  if mitigation.startswith('syn_pow_'):
    p['mitigation'] = "syn_pow"
    p['syn_pow_k'] = mitigation.split('_')[-1]
  else:
    p['mitigation'] = mitigation
    p['syn_pow_k'] = -1

  if len(p['attack_mitigation_pair']) > 2:
    p['mitigated_attack_type'] = p['attack_mitigation_pair'][2]
  else:
    p['mitigated_attack_type'] = attack_type
  p['attack_mitigation_pair'] = '"' + ','.join(p['attack_mitigation_pair']) + '"'

  

n_permutations = len(permutations)
print("Testing {} different permutations of experiment parameters".format(n_permutations))
i=0
for p in permutations:
  if i < skip_n:
    i += 1
    print("Skipping experiment {}/{} with the following parameters:".format(i, n_permutations))
    pprint(p)
    continue
  else:
    i += 1
  timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
  print("Starting experiment {}/{} at time {} with the following parameters:".format(i, n_permutations, timestamp))
  pprint(p)

  shutil.copyfile("{}/settings".format(code_dir), "{}/.settings".format(code_dir))
  with open("{}/.settings".format(code_dir), "a") as f:
    for k, v in p.items():
      f.write("{}={}\n".format(k, v))
    f.write("session={}\n".format(session))

  try:
    os.remove(tmp_log_path)
  except FileNotFoundError:
    pass

  mitigation = p['mitigation']
  subprocess.run(["{}/inventory_update.sh".format(code_dir)])
  subprocess.run(["{}/play".format(code_dir), "experiment", "timestamp={} mitigation={}".format(timestamp, mitigation)])
  subprocess.run(["mv", tmp_log_path, "{}/{}/.ansible.log".format(log_dir, timestamp)])
