from datetime import datetime
import itertools
import json
from pprint import pprint
import os
import shutil
import subprocess
import sys


code_dir = "/usr/local/dos-mitigation"

print("Generating Inventory")
subprocess.run(["./inventory_gen.sh"])

param_file = "{}/parameters.json".format(code_dir)
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
  i += 1
  print("Describing experiment {}/{} with the following parameters:".format(i, n_permutations))
  pprint(p)
