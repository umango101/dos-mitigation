from datetime import datetime
import itertools
import json
from pprint import pprint
import os
import shutil
import subprocess
import sys

session = sys.argv[1]
tmp_log_path = "/tmp/ansible.log"
code_dir = "/usr/local/dos-mitigation"

print("Generating Inventory")
subprocess.run(["./inventory_gen.sh"])

log_dir = "{}/logs/{}".format(code_dir, session)
os.makedirs(log_dir)
param_file = "{}/.parameters.json".format(log_dir)
shutil.copyfile("{}/parameters.json".format(code_dir), param_file)
with open(param_file) as f:
  params = json.load(f)

with open('{}/mitigated_attack_types.json'.format(code_dir)) as f:
  mitigated_attack_types = json.load(f)

keys, values = zip(*params.items())
permutations = [dict(zip(keys, v)) for v in itertools.product(*values)]

expanded_permutations = []
for p in permutations:
  mitigation = p['mitigation']
  attack_type = p['attack_type']
  mitigated_attack_set = [attack_type]
  if mitigation in mitigated_attack_types:
    if attack_type in mitigated_attack_types[mitigation]:
      mitigated_attack_set = mitigated_attack_types[mitigation][attack_type]
  for mitigated_attack_type in mitigated_attack_set:
    new_p = p.copy()
    new_p["mitigated_attack_type"] = mitigated_attack_type
    expanded_permutations.append(new_p)

n_permutations = len(expanded_permutations)
print("Testing {} different permutations of experiment parameters".format(n_permutations))
i=0
for p in expanded_permutations:
  i += 1
  timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
  print("Starting experiment {}/{} at time {} with the following parameters:".format(i, n_permutations, timestamp))
  pprint(p)

  shutil.copyfile("{}/settings".format(code_dir), "{}/.settings".format(code_dir))
  with open("{}/.settings".format(code_dir), "a") as f:
    for k, v in p.items():
      f.write("{}={}\n".format(k, v))
    f.write("session={}\n".format(session))
    f.write("mitigated_attack_type={}".format(p["mitigated_attack_type"]))

  try:
    os.remove(tmp_log_path)
  except FileNotFoundError:
    pass
  
  subprocess.run(["{}/inventory_update.sh".format(code_dir)])
  subprocess.run(["{}/play".format(code_dir), "experiment", "timestamp={} mitigation={}".format(timestamp, mitigation)])
  subprocess.run(["mv", tmp_log_path, "{}/{}/.ansible.log".format(log_dir, timestamp)])
