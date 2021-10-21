from datetime import (datetime, timedelta)
from ipaddress import IPv4Address, IPv4Network
from ripe.atlas.cousteau import (Ping, Traceroute, AtlasSource, AtlasCreateRequest, AtlasResultsRequest, Measurement, AtlasStopRequest)
from random import sample, getrandbits
import json
from threading import Thread, Lock
from time import sleep
from Queue import Queue, Empty
import gzip
import pytricia
import glob
import logging


ATLAS_API_KEY = ""
STOP_MEASUREMENT_KEY = ""
DATABASE_PATH = "./db.tar.gz"
NUMBER_OF_REQUESTS = 10
NUMBER_OF_RANDOM_IPS = 3
TIME_INTERVALS = [timedelta(seconds=20), timedelta(seconds=20), timedelta(seconds=20),
                  timedelta(seconds=20), timedelta(seconds=20), timedelta(seconds=40),
                  timedelta(seconds=40), timedelta(seconds=40), timedelta(seconds=40),
                  timedelta(minutes=1), timedelta(minutes=1), timedelta(minutes=1),
                  timedelta(seconds=90), timedelta(minutes=2)]
SLEEP_PATTERN = [20, 20, 20, 20, 20, 40, 40, 40, 40, 60, 60, 60, 90, 120]

database_lock = Lock()
database = pytricia.PyTricia()  # contains only IPv4


def do_work(ip, announced, prefix_database, stop_queue, prefix_database_lock, coordinator_queue, measurement_queue):
    probe_ids = create_probe_ids(ip, announced, prefix_database, prefix_database_lock)
    if probe_ids:
        start_traceroute(ip, probe_ids, announced, prefix_database, prefix_database_lock, coordinator_queue)
        start_pings(ip, probe_ids, announced, prefix_database, stop_queue, prefix_database_lock, coordinator_queue, measurement_queue)
    coordinator_queue.put(ip + "-D")


def load_db(path):
    if not path:
        return

    db = gzip.open(path, 'r')

    db.readline()
    db.readline()
    db.readline()
    ip, port, proto = db.readline().split("\x00")[-1][:-1].split(",")
    database[ip] = [(port, proto)]

    for line in db:
        try:
            ip, port, proto = line[:-1].split(",")

            if not database.get(ip):
                database[ip] = [(port, proto)]
            else:
                database[ip].append((port, proto))

        except ValueError:
            logging.error("Error with line:")
            logging.error(line)


def getrandips(prefix, count):
    with database_lock:
        database[prefix] = 0  # need to set a entry to obtain the children
        children = database.children(prefix)
        del database[prefix]

    try:
        ips = sample(children, count)
    except ValueError:
        subnet = IPv4Network(unicode(prefix, "utf-8"))
        remaining_bits = subnet.max_prefixlen - subnet.prefixlen
        ips = [str(IPv4Address(subnet.network_address + long(1))),  # adds the first host address
               str(IPv4Address(subnet.network_address + long(2**remaining_bits-2)))]  # adds the last host address

        if len(children) > 0:
            ips = children + ips
            ips = ips[:count]

        for i in range(count-len(ips)):  # create random IPs since we have no in our DB
            bits = getrandbits(remaining_bits)
            addr = IPv4Address(subnet.network_address + bits)
            ips.append(str(addr))

    return ips


def coordinate(prefix, sc_name, time, stop_queue):
    logging.info("Invoker thread for prefix " + prefix + " was created")
    announcement = stop_queue is not None
    logging.info("This invoker is an annocuned one: " + str(announcement))
    base_name = prefix.replace("/", ":")
    filename_base = sc_name + '-' + base_name
    filename = filename_base + '-' + str(time)

    # if we are in withdrawal part, fetches information of announcement part of this prefix
    prefix_database = load_dict(filename_base + "-", announcement)

    thread_list = []
    prefix_database_lock = Lock()
    coordinator_queue = Queue()
    measurement_queue = Queue()

    if announcement:
        ips = getrandips(prefix, NUMBER_OF_RANDOM_IPS)

        for ip in ips:
            thread = Thread(target=do_work, name=ip, args=(ip, True, prefix_database, stop_queue, prefix_database_lock, coordinator_queue, measurement_queue))
            thread_list.append(thread)
            thread.start()

    else:
        for ip in prefix_database:
            thread = Thread(target=do_work, name=ip, args=(ip, False, prefix_database, stop_queue, prefix_database_lock, coordinator_queue, None))
            thread_list.append(thread)
            thread.start()

    # coordinator_queue gets signals from children
    # signal looks like:
    # $IP-[T|P|D]
    # T means traceroute done, P means ping done(filter for highest key in dict to save this ping), D means dead
    while len(thread_list):
        if stop_queue and not stop_queue.empty():
            for th in thread_list:
                th.join()

            break

        try:
            signal = coordinator_queue.get(True, 5)
            ip = signal.split("-")[0]
            if signal.endswith("P"):
                if announcement:
                    current_dict_entry = prefix_database[ip]['announcement']
                    counter = current_dict_entry['counter']
                    p_filename = filename_base + "_" + ip + "_P_" + str(counter) + "_announcement"

                else:
                    current_dict_entry = prefix_database[ip]['withdrawal']
                    counter = current_dict_entry['counter']
                    p_filename = filename_base + "_" + ip + "_P_" + str(counter) + "_withdraw"

                current_dict_entry['counter'] += 1
                if counter in current_dict_entry:
                    write_to_disk(p_filename, current_dict_entry[counter])
                else:
                    logging.info("No " + str(counter) + " in dict entry")
                    logging.info(current_dict_entry)

            elif signal.endswith("T"):
                if announcement:
                    tr_filename1 = filename_base + "_" + ip + "_T1_announcement"
                    current_dict_entry1 = prefix_database[ip]['announcement']['traceroute1']
                    tr_filename2 = filename_base + "_" + ip + "_T2_announcement"
                    current_dict_entry2 = prefix_database[ip]['announcement']['traceroute2']
                    write_to_disk(tr_filename2, current_dict_entry2)

                else:
                    tr_filename1 = filename_base + "_" + ip + "_T1_withdraw"
                    current_dict_entry1 = prefix_database[ip]['withdrawal']['traceroute1']

                write_to_disk(tr_filename1, current_dict_entry1)

            else:
                thread_list = filter(lambda thr: thr.name != ip, thread_list)

        except Empty:
            continue

    while not measurement_queue.empty():
        stop_queue.get()  # main will always send a stop and we want the ping measurements to stop then
        measurement_id = measurement_queue.get()
        logging.info("Stop measurement with id " + str(measurement_id))
        AtlasStopRequest(msm_id=measurement_id, key=STOP_MEASUREMENT_KEY).create()

    write_to_disk(filename, prefix_database)


def start_traceroute(destination_ip, probe_ids, announced, prefix_database, prefix_database_lock, coordinator_queue):
    if announced:
        with prefix_database_lock:
            current_dict_entry = prefix_database[destination_ip]['announcement']
    else:
        with prefix_database_lock:
            current_dict_entry = prefix_database[destination_ip]['withdrawal']

    source = AtlasSource(
        type="probes",
        value=str(probe_ids)[1:-1],
        requested=len(probe_ids)
    )

    try:
        port, proto = database[destination_ip][0]
    except KeyError:
        port = 80
        proto = "ICMP"

    traceroute = Traceroute(
        af=4,  # ipv4
        target=destination_ip,
        description="testing",
        protocol=proto,
        port=port,
    )

    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=[traceroute],
        sources=[source],
        is_oneoff=True
    )

    is_success, response = atlas_request.create()
    if not is_success:
        logging.error("First traceroute of IP " + destination_ip + " was not succesful")
        logging.error(response)
    else:
        current_dict_entry['traceroute1'] = response['measurements'][0]

    if announced:
        atlas_request = AtlasCreateRequest(
            start_time=datetime.utcnow() + timedelta(minutes=30),
            key=ATLAS_API_KEY,
            measurements=[traceroute],
            sources=[source],
            is_oneoff=True
        )

        is_success, response = atlas_request.create()
        if not is_success:
            logging.error("Second traceroute of IP " + destination_ip + " was not succesful")
            logging.error(response)
        else:
            measurement_id = response['measurements'][0]
            current_dict_entry['traceroute2'] = measurement_id

    coordinator_queue.put(destination_ip + "-T")


def start_pings(destination_ip, probe_ids, announced, prefix_database, stop_queue, prefix_database_lock, coordinator_queue, measurement_queue):
    ping = Ping(af=4, target=destination_ip, description="testing")
    error_counter = 0

    source = AtlasSource(
        type="probes",
        value=str(probe_ids)[1:-1],
        requested=len(probe_ids)
    )

    if announced:
        with prefix_database_lock:
            current_dict_entry = prefix_database[destination_ip]['announcement']
            current_dict_entry['counter'] = 0
        should_work = True
        sleep_index = 0

        while should_work:
            atlas_request = AtlasCreateRequest(
                start_time=datetime.utcnow()+timedelta(seconds=5),
                key=ATLAS_API_KEY,
                measurements=[ping],
                sources=[source],
                is_oneoff=True
            )

            is_success, response = atlas_request.create()

            if is_success:
                error_counter = 0
                try:
                    current_dict_entry[sleep_index] = response['measurements'][0]
                except TypeError as e:
                    logging.error(e)
                    logging.error(response)
                    logging.error(sleep_index)
                    logging.error(current_dict_entry)
            else:
                error_counter += 1
                logging.error("Ping of " + destination_ip + " was an error:")
                logging.error(response)
            coordinator_queue.put(destination_ip + "-P")  # this signal is important for the counter in coordinate function
            if error_counter == 3:
                return

            if sleep_index < len(SLEEP_PATTERN):
                sleep(SLEEP_PATTERN[sleep_index])
            else:
                sleep_index += 1
                atlas_request = AtlasCreateRequest(
                    start_time=datetime.utcnow()+timedelta(seconds=5),
                    stop_time=datetime.utcnow() + timedelta(hours=1),
                    key=ATLAS_API_KEY,
                    measurements=[ping],
                    sources=[source],
                    is_oneoff=False  # this will run measurements until end time or until a stop signal comes
                )

                is_success, response = atlas_request.create()

                if is_success:
                    try:
                        measurement_id = response['measurements'][0]
                        current_dict_entry[sleep_index] = measurement_id
                        measurement_queue.put(measurement_id)
                    except TypeError as e:
                        logging.error(e)
                        logging.error(response)
                        logging.error(sleep_index)
                        logging.error(current_dict_entry)
                else:
                    logging.error("Ping of " + destination_ip + " was an error:")
                    logging.error(response)
                coordinator_queue.put(destination_ip + "-P")  # this signal is important for the counter in coordinate function

                return

            sleep_index += 1
            should_work = stop_queue.empty()

    else:
        with prefix_database_lock:
            current_dict_entry = prefix_database[destination_ip]['withdrawal']
            current_dict_entry['counter'] = 0
        counter = 0
        for delta in TIME_INTERVALS:  # starts ping requests in
            atlas_request = AtlasCreateRequest(
                start_time=datetime.utcnow() + delta,
                key=ATLAS_API_KEY,
                measurements=[ping],
                sources=[source],
                is_oneoff=True
            )

            is_success, response = atlas_request.create()


            # saves the measurement IDs in the dict under ip:seconds:[]
            if is_success:
                error_counter = 0
                current_dict_entry[counter] = response['measurements'][0]
            else:
                error_counter += 1
            coordinator_queue.put(destination_ip + "-P")  # this signal is important for the counter in coordinate function
            if error_counter == 3:
                return

            counter += 1


def create_probe_ids(destination_ip, announced, prefix_database, prefix_database_lock):
    ping = Ping(af=4, target=destination_ip, description="testing")
    probe_ids =[]

    if announced:
        with prefix_database_lock:
            prefix_database[destination_ip] = {'announcement': {}, 'withdrawal': {}}
            current_dict_entry = prefix_database[destination_ip]['announcement']

        source = AtlasSource(
            type="area",
            value="WW",
            requested=NUMBER_OF_REQUESTS,
            tags={"include": ["system-ipv4-stable-90d"]}
        )

        atlas_request = AtlasCreateRequest(
            start_time=datetime.utcnow(),
            key=ATLAS_API_KEY,
            measurements=[ping],
            sources=[source],
            is_oneoff=True
        )

        is_success, response = atlas_request.create()

        measurement_id = response['measurements'][0]
        is_success, results = AtlasResultsRequest(**{"msm_id": measurement_id}).create()

        iterator = 0
        if is_success:
            status = Measurement(id=measurement_id).status
        else:
            status = ''
        while len(results) != NUMBER_OF_REQUESTS and status != u'Stopped':
            is_success, results = AtlasResultsRequest(**{"msm_id": measurement_id}).create()
            if is_success:
                status = Measurement(id=measurement_id).status
            sleep(1)
            iterator += 1
            if iterator == 1000:
                break

        try:
            probe_ids = map(lambda i: i['prb_id'], results)
        except TypeError as e:
            logging.error("Could not create probe ids for IP " + destination_ip)
            logging.error(e)
            logging.error(str(results))
            exit(1)
        current_dict_entry['probes'] = probe_ids  # saves the probe IDs in the dict under ip:probes:[]

        return probe_ids

    else:
        with prefix_database_lock:
            return prefix_database[destination_ip]['announcement']['probes']


def write_to_disk(filename, prefix_database):
    with open(filename, 'w+') as fd:
        json.dump(prefix_database, fd)  # writes the whole dictionary to the file


def load_dict(filename, announcement):
    logging.info("loading dict: " + filename)
    if not announcement:
        found = False
        announcement_file = ""
        error_counter = 0
        while not found:  # while loop is used if announcement is not saved at this moment
            max_time = 0
            for name in glob.glob(filename + "*"):
                found = True
                time = float(name.split("-")[-1])
                if time > max_time:
                    announcement_file = name
                    max_time = max(max_time, time)
            if not found:
                sleep(5)  # avoid busy wait
                error_counter += 1
                if error_counter == 20:
                    raise IOError

        try:
            with open(announcement_file) as fd:
                prefix_database = json.load(fd)  # loads the dictionary from the file if this is a withdrawal
                return prefix_database
        except IOError:
            logging.error("Couldn't find announcement file")  # should not happen
            exit(1)

    else:
        return dict()

