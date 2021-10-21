from datetime import *
from Queue import Queue
from threading import Thread

import pytricia
import pybgpstream
import json
import measurement
import sys
import getopt
import logging
import glob

UPDATE_THRESHOLD = 100
UPDATE_DELAY = 400
MEASUREMENT_THRESHOLD = 1
measurement_counter = 0


def build_trees(filename, as_number):
    pyt_v4 = pytricia.PyTricia()
    try:
        with open(filename, 'r') as fd:
            for line in fd:
                ip_type, asn, prefixes = line.split("|")
                if asn != as_number and asn != "UNALLOCATED":
                    continue

                if ip_type.endswith("V4"):
                    for prefix in prefixes.split("_"):
                        pyt_v4.insert(prefix, ip_type)
                else:
                    continue  # for IPv6 support
                    # for prefix in prefixes.split("_"):
                    #     pyt_v6.insert(prefix, ip_type)
    except IOError:
        pass

    return pyt_v4  # , pyt_v6


def check_time(update_time):
    unix_time = (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
    return unix_time - UPDATE_DELAY < update_time


def get_latest_rib_stream(as_number):
    current_time = datetime.utcnow().time()
    if current_time < time(9):
        start_time = datetime.combine(date.today(), datetime.min.time())
    elif current_time > time(17):
        start_time = datetime.combine(date.today(), time(16))
    else:
        start_time = datetime.combine(date.today(), time(8))

    return pybgpstream.BGPStream(
        filter='ipversion 4 and path "_' + as_number + '$"',
        projects=['ris'],
        from_time=str(start_time),
    )


def call_measurement(prefix, sc_name, timestamp, command_queue):
    measurement.coordinate(prefix, sc_name, timestamp, command_queue)


def save_as_updates(prefix, sc_name, prefix_data):
    base_name = prefix.replace("/", ":")
    filename = base_name + '-' + sc_name + '-' + str(prefix_data[prefix]['start_time']) + '_updates'
    with open(filename, 'w+') as fd:
        json.dump(prefix_data, fd)  # writes the whole dictionary to the file


def main(sc_name, ribs_enabled, path):
    global measurement_counter

    logging.info("Start to build the blacklist")
    tree_v4 = build_trees(path, sc_name)  # building blocklist
    logging.info("Blacklist has length: " + str(len(tree_v4)))
    logging.info("Start to load the IP database")
    measurement.load_db(measurement.DATABASE_PATH)  # building target selection list

    updates = dict()

    logging.info("Get latest rib stream")
    stream = get_latest_rib_stream(sc_name)

    logging.info("Start building update database")
    for rec in stream:
        for elem in rec:
            prefix = elem.fields['prefix']

            if tree_v4.get(prefix):  # filter out prefixes that belong to the as company as well as longer ones
                continue

            if ribs_enabled:
                if elem.type == 'R':
                    if not (prefix in updates):
                        updates[prefix] = {'announcement': {'counter': 1}, 'withdrawal': {'counter': 0}, 'start_time': None,
                                           'stop_thread_queue': None}
                        if not (elem.peer_asn in updates[prefix]['announcement']):
                            updates[prefix]['announcement'][elem.peer_asn] = elem.time

                else:
                    if check_time(rec.time):
                        logging.info("Now we are in real time")
                        ribs_enabled = False

                    if elem.type == "A":
                        if not (prefix in updates):
                            updates[prefix] = {'announcement': {'counter': 1}, 'withdrawal': {'counter': 0}, 'start_time': None,
                                               'stop_thread_queue': None}
                        else:
                            updates[prefix]['announcement']['counter'] += 1
                        if not (elem.peer_asn in updates[prefix]['announcement']):
                            updates[prefix]['announcement'][elem.peer_asn] = elem.time

                    elif elem.type == "W":
                        if prefix in updates:
                            if not (elem.peer_asn in updates[prefix]['announcement']):
                                updates[prefix]['withdrawal'][elem.peer_asn] = elem.time
                            if updates[prefix]['withdrawal']['counter'] > UPDATE_THRESHOLD:
                                save_as_updates(prefix, elem.peer_asn, updates[prefix])
                                del updates[prefix]

            else:
                if elem.type == 'A':
                    if not (prefix in updates):
                        stop_queue = Queue()
                        updates[prefix] = {'announcement': {'counter': 1}, 'withdrawal': {'counter': 0}, 'start_time': elem.time,
                                           'stop_thread_queue': stop_queue}

                    else:
                        updates[prefix]['announcement']['counter'] += 1

                    if not (elem.peer_asn in updates[prefix]['announcement']):
                        updates[prefix]['announcement'][elem.peer_asn] = elem.time
                    if updates[prefix]['announcement']['counter'] == UPDATE_THRESHOLD:
                        # limitation part
                        files = glob.glob('*')
                        files = filter(lambda x: not x.startswith(as_num), files)
                        if len(files) > 11:  # check if other as had a protection event
                            continue

                        if measurement_counter >= MEASUREMENT_THRESHOLD:
                            continue
                        else:
                            measurement_counter += 1

                        stop_queue = updates[prefix]['stop_thread_queue']
                        if stop_queue is None:  # addition in order to only start measurements for recent prefixes
                            continue
                        Thread(target=call_measurement,
                               args=(prefix, sc_name, elem.time, stop_queue)).start()
                        logging.info("Reached threshold for prefix " + prefix)

                elif elem.type == 'W':
                    if prefix in updates:
                        updates[prefix]['withdrawal']['counter'] += 1
                        if updates[prefix]['withdrawal']['counter'] == 1:
                            updates[prefix]['end_time'] = elem.time
                        if not (elem.peer_asn in updates[prefix]['announcement']):
                            updates[prefix]['withdrawal'][elem.peer_asn] = elem.time

                        if updates[prefix]['withdrawal']['counter'] == UPDATE_THRESHOLD:
                            stop_queue = updates[prefix]['stop_thread_queue']
                            if stop_queue and stop_queue.empty():
                                stop_queue.put(True)

                                Thread(target=call_measurement,
                                       args=(prefix, sc_name, elem.time, None)).start()

                        if updates[prefix]['withdrawal']['counter'] > UPDATE_THRESHOLD * 2:
                            if updates[prefix]['stop_thread_queue']:
                                measurement_counter -= 1
                            logging.info("Deleting entry for prefix " + prefix)
                            del updates[prefix]  # just some cleanup since all measurements should be started


if __name__ == '__main__':
    collect_ribs = True
    as_num = None
    filepath = None

    arg_list = sys.argv[1:]
    short_options = "n:rp:"
    long_options = ["asnumber=", "ribs", "path="]

    try:
        arguments, values = getopt.getopt(arg_list, short_options, long_options)

        for argument, value in arguments:
            if argument in ("-n", "--asnumber"):
                as_num = value
            if argument in ("-p", "--path"):
                filepath = value
            if argument in ("-r", "--ribs"):
                collect_ribs = False

        if not as_num:
            print("No AS number given.")
            exit(1)
        if not filepath:
            print("No filepath given.")
            exit(1)

        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            filename=as_num + '_main.log')
        main(as_num, collect_ribs, filepath)

    except getopt.error as err:
        print(str(err))
        exit(1)

    except KeyboardInterrupt:
        sys.exit(0)
