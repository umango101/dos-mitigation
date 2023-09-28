# Tools for DoS mitigation research

Author: Samuel DeLaughter
License: MIT

## Overview

This repository contains versions of the tools I developed for Denial-of-Service mitigation research during my PhD.  It includes scripts for both generating and mitigating volumetric flooding attacks, as well as tools for automating the experimentation process.  Automation tools assume the use of a Merge-based testbed like DeterLab, but files in the `common` directory are general purpose, and should function across most Linux systems.  The next section provides instructions for running experiments in Merge, with documentation for other utilities following.

This code is intended for research purposes only.  Please use it responsibly.

## Merge Setup

These instructions assume you have already materialized an [experiment] in Merge (https://mergetb.org/docs/experimentation/hello-world/), connected it to an [XDC](https://mergetb.org/docs/experimentation/xdc/), and installed the [Merge CLI](https://gitlab.com/mergetb/portal/cli) on that XDC.
The following steps should need to be done infrequently, when first setting up a new experiment and XDC.  Step 8 will need to be repeated anytime you make changes to this repository that you want to be reflected on testbed devices.

1. Clone (a fork of) this respository to your XDC, at `~/dos-mitigation`
2. `ssh` to your XDC and run `cd ~/dos-mitigation` to enter the directory
3. Update `settings` with your own credentials and testbed settings
4. Run `sudo xdc_setup.sh` to install dependencies and configure the XDC
5. Run `mrg login [your Merge username]` to login to the Merge testbed.  Note that you will typically need to repeat this step each time you connect to the XDC, and at least once per day for long-running connections.
6. Run `inventory_gen.sh` to build inventory files listing the devices in your network.
7. Run `play depends` to install dependencies on testbed devices.  This will also run the `push_common.yml` playbook which copies repository files to testbed devices.  If you make changes to this code later, run `play push_common` to propagate them.

## Running Experiments

1. `ssh` to your XDC and run `cd ~/dos-mitigation` to enter the directory
2. Optionally, run `play ping` to ensure that all devices in your network are up and able to reach the server.  You can also use `play debug` to view detailed information about each device.
3. Update `parameters.json` with the set of variables you want to test in a session of experiments.  The format is a dictionary in which keys are parameter names and values are a list of list of corresponding parameter values.  All possible combinations will be tested by `run.py`, such that this dictionary...
    ```
    {
        "foo": [0, 1],
        "bar": ["a", "b"]
    }
    ```

    ...will result in four sets of experiments with the following settings:

    ```
    foo=0, bar="a"
    foo=0, bar="b"
    foo=1, bar="a"
    foo=1, bar="b"
    ```
4. Run `mrg login [your Merge username]` to make sure you're logged in.
5. Run `python3 ./run.py session_name` to run a set of experiments.  Results will be stored in `~/dos-mitigation/logs/session_name`.  Except when debugging, it's recommended to run this command via `screen` so that you can close the SSH session without disrupting long-running experiments, and return later to check on the results.  So, run `screen python3 ./run.py session_name` to start experiments, then press `Ctrl-A-D` to detach the screen and run `screen -r` to reattach it.<br>For each set of experiment parameters, as described above, `run.py` will create a new temporary `.settings` file, concatenating `settings` and the `hosts` inventory file (note that some additional settings are added via `inventory_update.sh` -- in a future version these will hopefully be moved to the model file and captured automatically at inventory generation).  Results for each experiment will be stored in a subdirectory of `~/dos-mitigation/logs/session_name`, named with a timestamp indicating when that experiment began.

## Common Files

### Mitigations
The code for our DoS mitigations is primarily split across the `common/ebpf` and `common/mitigations` directories.  The former contains source code in eBPF-compatible C, while the latter contains shell scripts to simplify the process of compiling that source code and attaching the eBPF programs to network devices.

#### SYN PoW
Adds a small proof-of-work to TCP SYN Packets

#### SYN Padding
Adds a padding to TCP SYN Packets

### Attacks
These scripts pose a serious danger if not used with care -- they are to be used for research purposes only, in controlled environemnts.  Even then, precautions must be taken to avoid flooding devices outside your control -- if using address-spoofing features, make sure response traffic is dropped rather than delivering it to the rightful address owners.  When operating on DeterLab, `run.py` will call `playbooks\route_config.yml`, which configures devices to route outbound traffic (with public destination IPs) towards a **Sink** device where it is then dropped.  Note that routining this attack backscatter through the network is important for maintaining realism in experimentation, but dropping it before it leaves the testbed is essential.

#### SYN Flood

#### UDP Flood

### Clients

#### TCP

#### HTTP

#### ICMP
