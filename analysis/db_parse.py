import db_helpers as dbh
import json
import math
import os
import pandas as pd
from parse_config import parse_config
from psycopg2.extras import execute_values
from pprint import pprint
from datetime import datetime


log_dir = "/usr/local/dos-mitigation/data"
db_name = "dos"

maximize_metrics = ['Transaction Status', "Transactions per Second", "Average Transactions per Second"]
minimize_metrics = ['Transaction Duration']
tps_bin_size = 1

def parse_csv(path):
    # print("Parsing TCP log: {}".format(path))
    success_data = []
    failure_data = []

    with open(path, 'r') as f:
        lines = f.readlines()
    if len(lines) < 2:
        failure_data = [(0, 1)]
        return success_data, failure_data
    
    min_time = int(lines[1].strip().split(',')[1])

    first_failure = None
    for line in lines[1:]:
        line = line.strip().split(',')
        status = int(line[0])
        start = (int(line[1]) - min_time) / 1000000000.0
        end = (int(line[2]) - min_time) / 1000000000.0

        if status == 0:
            if first_failure != None:
                start = first_failure
            success_data.append((start, end-start))
            first_failure = None
        else:
            if first_failure == None:
                first_failure = start
            failure_data.append((start, status))

    return success_data, failure_data


def parse_materialization(conn, materialization):
    print("Parsing materialization: {}".format(materialization))
    for session in os.listdir("{}/{}".format(log_dir, materialization)):
        if session.startswith('.'):
            continue
        parse_session(conn, materialization, session)

def parse_session(conn: dbh.Connection, materialization, session):
    print("Parsing session: {}".format(session))

    materialization_id = conn.nickname_id("materializations", materialization)

    if conn.value_in_column('sessions', 'nickname', session):
        print("A session with the nickname {} already exists.".format(session))
        op = input("\t(C)ancel | (a)ppend | (o)verwrite : ")
        op = op.lower()
        if op in ['a', 'append']:
            pass
        elif op in ['o', 'overwrite']:
            confirmation = input("Are you sure? (y/N)")
            if confirmation.lower() in ['y', 'yes']:
                # To Do
                pass
            else:
                print("Cancelling")
                return

            pass
        else:
            return

    with open("{}/{}/{}/.parameters.json".format(log_dir, materialization, session)) as f:
        parameters = json.load(f)

    session_row = {
        "materialization": [materialization_id],
        "parameters": [json.dump(parameters)]
    }
    df = pd.DataFrame.from_dict(session_row)
    conn.bulk_insert("sessions", df)

    for experiment in os.listdir("{}/{}/{}".format(log_dir, materialization, session)):
        if experiment.startswith('.'): 
            continue
        parse_experiment(conn, materialization, session, experiment, tps_bin_size)


def parse_experiment(conn: dbh.Connection, materialization, session, experiment, tps_bin=1):
    print("Parsing experiment: {}".format(experiment))

    # timestamp = datetime.fromisoformat(experiment)
    timestamp = datetime.strptime(experiment, "%Y_%m_%d_%H_%M_%S")

    materialization_id = conn.nickname_id("materializations", materialization)
    session_id = conn.nickname_id("sessions", session)

    config = parse_config("{}/{}/{}/{}/.settings".format(log_dir, materialization, session, experiment))
    exp_row = {}
    exp_row['settings'] = config
    exp_row['timestamp'] = timestamp
    exp_row['session'] = session_id
    conn.insert_dict_as_row("experiments", exp_row)
    experiment_id = conn.nickname_id("experiments", timestamp, "timestamp")

    for host in os.listdir("{}/{}/{}/{}".format(log_dir, materialization, session, experiment)):
        if host.startswith('.'):
            continue
        
        hostgroup, hostnum = dbh.parse_hostname(host)
        host_id = dbh.result_as_value(conn.db_query("select id from hosts where hostname = '{}' and materialization = '{}'".format(host, materialization_id)))
        if host_id == []:
            host_row = {
                "materialization": materialization_id,
                "hostname": host,
                "hostgroup": hostgroup,
                "hostnum": hostnum
            }
            conn.insert_dict_as_row("hosts", host_row)
            host_id = dbh.result_as_value(conn.db_query("select id from hosts where hostname = '{}' and materialization = '{}'".format(host, materialization_id)))

        for mode in ["UB", "MB", "UA", "MA"]:
            attack_enabled = mode in ["UA", "MA"]
            mitigation_enabled = mode in ["MB", "MA"]
            try:
                log_files = os.listdir("{}/{}/{}/{}/{}/{}/logs".format(log_dir, materialization, session, experiment, host, mode))
            except FileNotFoundError as e:
                continue
            for filename in log_files:
                if filename.startswith('.'):
                    continue
                if filename.endswith('.zip'):
                    continue
                path = "{}/{}/{}/{}/{}/{}/logs/{}".format(log_dir, materialization, session, experiment, host, mode, filename)
                if filename in ["tcp.csv", "http.csv", "https.csv", "http3.csv"]:
                    success_data, failure_data = parse_csv(path)
                    query = "insert into data (metric, host, experiment, attack_enabled, mitigation_enabled, timestamp, value) VALUES %s"
                    for data, metric in [
                        (success_data, "Transaction Duration"),
                        (failure_data, "Transaction Status")
                    ]:              
                        template = "('{}', {}, {}, {}, {}, %s, %s)".format(metric, host_id, experiment_id, attack_enabled, mitigation_enabled)
                        with conn.conn.cursor() as c:
                            execute_values(
                                cur=c,
                                sql=query,
                                argslist=data,
                                template=template,
                                page_size=100,
                                fetch=False
                            )
                    duration = dbh.result_as_value(conn.db_query("select settings['client_duration'] from experiments where id = {}".format(experiment_id)))

                    average_tps = len(success_data)/float(duration)
                    conn.insert_dict_as_row("data", {
                        'metric': "Average Transactions per Second",
                        'host': host_id,
                        'experiment': experiment_id,
                        'attack_enabled': attack_enabled,
                        'mitigation_enabled': mitigation_enabled,
                        'timestamp': None,
                        'value': average_tps
                    })

                    if tps_bin > 0:
                        binned_success_data = {}
                        for start, duration in success_data:
                            bin_number = math.floor((float(start)+float(duration))/ tps_bin) # based on end time
                            if bin_number in binned_success_data:
                                binned_success_data[bin_number] += 1
                            else:
                                binned_success_data[bin_number] = 1
                        for bin, n_success in binned_success_data.items():
                            tps = float(n_success / tps_bin)
                            conn.insert_dict_as_row("data", {
                                'metric': "Transactions per Second",
                                'host': host_id,
                                'experiment': experiment_id,
                                'attack_enabled': attack_enabled,
                                'mitigation_enabled': mitigation_enabled,
                                'timestamp': None,
                                'value': tps
                            })
                    else:
                        tps = average_tps
                        conn.insert_dict_as_row("data", {
                            'metric': "Transactions per Second",
                            'host': host_id,
                            'experiment': experiment_id,
                            'attack_enabled': attack_enabled,
                            'mitigation_enabled': mitigation_enabled,
                            'timestamp': None,
                            'value': tps
                        })

                else:
                    continue


def analyze_experiment(conn: dbh.Connection, experiment):
    # print("Analyzing experiment {}".format(experiment))
    timestamp = datetime.strptime(experiment, "%Y_%m_%d_%H_%M_%S")
    experiment_id = conn.nickname_id("experiments", timestamp, "timestamp")
    query = "SELECT DISTINCT metric FROM data WHERE experiment = {}".format(experiment_id)
    metric_list = dbh.result_as_list(conn.db_query(query))
    for metric in metric_list:
        # print("Analyzing metric {}".format(metric))
        minimize = metric in minimize_metrics
        if not minimize and metric not in maximize_metrics:
            print("Encountered metric with unknown optimization direction: {}".format(metric))
            continue

        query = """
            SELECT
                host,
                CASE
                    WHEN mitigation_enabled IS FALSE
                        AND attack_enabled IS FALSE THEN 'ub'
                    WHEN mitigation_enabled IS TRUE
                        AND attack_enabled IS FALSE THEN 'mb'
                    WHEN mitigation_enabled IS FALSE
                        AND attack_enabled IS TRUE THEN 'ua'
                    WHEN mitigation_enabled IS TRUE
                        AND attack_enabled IS TRUE THEN 'ma'
                END mode,
                AVG(value)
            FROM data
            WHERE
                experiment = {} AND metric = '{}'
            GROUP BY host, mode
        """.format(experiment_id, metric)

        data = conn.db_query(query)
        data_dict = {}
        for host_id, mode, value in data:
            if host_id not in data_dict:
                data_dict[host_id] = {}
            data_dict[host_id][mode] = value
        for host_id, d in data_dict.items():
            for m in ["ub", "mb", "ua", "ma"]:
                if m not in d:
                    d[m] = 0

            UB = d["ub"]
            MB = d["mb"]
            UA = d["ua"]
            MA = d["ma"]

            baseline = UB
            threat = baseline - UA
            damage = baseline - MA
            overhead = baseline - MB
            if minimize:
                threat *= -1.0
                damage *= -1.0
                overhead *= -1.0
            
            efficacy = threat - damage

            if baseline == 0:
                damage_pct = 0
                threat_pct = 0
                overhead_pct = 0
                efficacy_pct = 0
            else:
                damage_pct = (damage / baseline) * 100.0
                threat_pct = (threat / baseline) * 100.0
                overhead_pct = (overhead / baseline) * 100.0
                efficacy_pct = (efficacy / baseline) * 100.0

            if (threat <= 0):
                efficacy_pct_threat = 0
            else:
                efficacy_pct_threat = (efficacy / threat) * 100.0

            if efficacy_pct > 0:
                if (threat_pct <= 0):
                    efficacy_relative = 0
                else:
                    efficacy_relative = efficacy_pct * (threat_pct / 100.0)
            else:
                 efficacy_relative = efficacy_pct

            result_row = {
                "experiment": experiment_id,
                "metric": metric,
                "host": host_id,
                "ub": UB,
                "mb": MB,
                "ua": UA,
                "ma": MA,
                "threat": threat,
                "damage": damage,
                "efficacy": efficacy,
                "overhead": overhead,
                "threat_pct": threat_pct,
                "damage_pct": damage_pct,
                "efficacy_pct": efficacy_pct,
                "efficacy_pct_threat": efficacy_pct_threat,
                "efficacy_relative": efficacy_relative,
                "overhead_pct": overhead_pct
            }
            conn.insert_dict_as_row("results", result_row)

    # mean_tps = db.groupby(["mode"])["tps"].mean()
    # if mean_tps["UB"] == 0 :
    #     n_bad+=1
    #     # print("!!! 0 baseline for experiment {} with settings:".format(experiment))
    #     # for i in ["client_interval",
    #     #           "attacker_busywait",
    #     #           "bottleneck_capacity",
    #     #           "bottleneck_latency"]:
    #     #     print("{}: {}".format(i, config[i]))
    #     continue
    # else:
    #     n_good+=1
    #     # print("+++ {} baseline for experiment {} with settings:".format(mean_tps["UB"], experiment))
    #     # for i in ["client_interval",
    #     #       "attacker_busywait",
    #     #       "bottleneck_capacity",
    #     #       "bottleneck_latency"]:
    #     #     print("{}: {}".format(i, config[i]))
    # overhead = ((mean_tps["UB"] - mean_tps["MB"]) / mean_tps["UB"]) * 100.0
    # threat = ((mean_tps["UB"] - mean_tps["UA"]) / mean_tps["UB"]) * 100.0
    # damage = ((mean_tps["UB"] - mean_tps["MA"]) / mean_tps["UB"]) * 100.0
    # if threat <= 0:
    #     efficacy = None
    # else:
    #     efficacy = ((threat - damage) / threat) * 100.0
    #
    # stats = {
    #     "Mitigation": config['mitigation'],
    #     "Attack Vector": config['attack_type'],
    #     "Clients": int(config['n_clients']),
    #     "Attackers": int(config['n_attackers']),
    #     "Client Interval (s)": float(config['client_interval']),
    #     "Attacker Delay (Ops/Packet)": float(config['attacker_busywait']),
    #     "Attack Rate (Mbps)": attack_rate_map[float(config['attacker_busywait'])] * int(config['n_attackers']),
    #     "Bottleneck Link Capacity (Mbps)": int(config['bottleneck_capacity']),
    #     "Bottleneck Link Latency (ms)": int(config['bottleneck_latency']),
    #     "Unmitigated Baseline": mean_tps["UB"],
    #     "Mitigated Baseline": mean_tps["MB"],
    #     "Unmitigated Attack": mean_tps["UA"],
    #     "Mitigated Attack": mean_tps["MA"],
    #     "Overhead": overhead,
    #     "Threat": threat,
    #     "Damage": damage,
    #     "Efficacy": efficacy,
    #     "Server Baseline": mean_tps["UB"]*int(config['n_clients'])
    # }
    # data = pd.concat([data, pd.DataFrame(stats, index=[0])], ignore_index=True);
