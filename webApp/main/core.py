from django.conf import settings

# from main.models import ScanRecord

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split

import pandas as pd
import matplotlib.pyplot as plt
import xgboost as xgb
import joblib
from scapy.all import *
from collections import defaultdict
import time
import csv
import os
import socket
import netifaces as ni
from configparser import ConfigParser

STOP_FLAG = False
START_TIME = None
STOP_TIME = None

config = ConfigParser()
config.read(os.path.join(settings.STATICFILES_DIRS[0], 'config.ini'))

ENGINE = config.get('system', 'engine')

PROTOCOL_LE_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'protocol_label_encoder.joblib')
SERVICE_LE_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'service_label_encoder.joblib')
FLAG_LE_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'flag_label_encoder.joblib')
ATTACK_LE_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'attack_label_encoder.joblib')
SCALER_LE_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'scaler.joblib')

RFC_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'random_forest_model.joblib')
XGB_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'joblibs', 'xgboost_model.joblib')

PACKETS_CSV_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'capture_history', 'running_scan.csv')

TRAIN_DATA_CSV_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'datasets', 'NSL_KDD', 'KDDTrain+.csv')
TEST_DATA_CSV_PATH = os.path.join(settings.STATICFILES_DIRS[0], 'datasets', 'NSL_KDD', 'KDDTest+.csv')




ATTACK_NAMES = {
    0: 'DoS',
    1: 'Normal',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R',
}

COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'level'
]

FEATURE_NAMES = COLUMN_NAMES[:-2]

# Map attack types to categories
ATTACK_MAPPING = {
    'normal': 'Normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
    'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'xsnoop': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
    'worm': 'U2R', 'snmpguess': 'U2R',
    'warezclient': 'R2L', 'multihop': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'xlock': 'R2L',
    'xsnoop': 'R2L'
}


PROTOCOL_TYPE_MAPPING = {6: 'tcp', 17: 'udp', 1: 'icmp'}

SERVICE_MAPPING = {
    20: 'ftp_data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain_u',
    67: 'dhcp',  # Common service not listed, but associated with port 67
    68: 'dhcp',  # Common service not listed, but associated with port 68
    69: 'tftp_u',
    70: 'gopher',
    79: 'finger',
    80: 'http',
    110: 'pop_3',
    111: 'sunrpc',
    113: 'auth',
    115: 'sftp',  # Common service not listed, but associated with port 115
    119: 'nntp',
    123: 'ntp_u',
    137: 'netbios_ns',
    138: 'netbios_dgm',
    139: 'netbios_ssn',
    143: 'imap4',
    161: 'snmp',  # Common service not listed, but associated with port 161
    194: 'IRC',
    443: 'http_443',
    445: 'microsoft-ds',  # Associated with SMB over TCP/IP
    512: 'exec',
    513: 'login',
    514: 'shell',
    515: 'printer',
    520: 'router',  # Common service associated with RIP
    543: 'klogin',
    544: 'kshell',
    548: 'afp',  # Apple Filing Protocol, not listed but commonly used
    993: 'imap_ssl',  # Common service not listed, but associated with port 993
    995: 'pop_ssl',   # Common service not listed, but associated with port 995
    1080: 'socks',  # Common service associated with SOCKS proxy
    1433: 'sql_net',
    1521: 'oracle',  # Common service not listed, but associated with port 1521
    2049: 'nfs',  # Common service associated with Network File System
    3306: 'mysql',   # Common service not listed, but associated with port 3306
    3389: 'rdp',     # Common service not listed, but associated with port 3389
    4000: 'remote_job',
    4662: 'edonkey',  # Common P2P service
    5432: 'postgresql',  # Common service associated with PostgreSQL
    6667: 'IRC',  # Alternative IRC port
    8080: 'http_8001',
    8081: 'http_2784',
    8443: 'https_alt',  # Common alternative HTTPS port
    27017: 'mongodb',  # Common service not listed, but associated with port 27017
    50000: 'private',  # Placeholder for private services
    62078: 'iphone-sync',  # Common service associated with iPhone sync
}

TIME_WINDOW = 120


SESSIONS = defaultdict(list)

HOST_STATS = defaultdict(lambda: {
    "srv_count": 0, "srv_error": 0, "diff_srv_count": 0,
    "same_src_port_count": 0, "srv_rerror_count": 0,
    "count": 0, "last_time": 0, "srv_diff_host_count": 0,
    "rerror_count": 0, "dst_host_count": 0, "srv_host_count": 0,
    "num_sessions": 0,
})





def setupDataset():
    # Load the dataset
    train_data = pd.read_csv(TRAIN_DATA_CSV_PATH, header=None)
    test_data = pd.read_csv(TEST_DATA_CSV_PATH, header=None)


    train_data.columns = COLUMN_NAMES
    test_data.columns = COLUMN_NAMES

    # Combine train and test data for preprocessing
    data = pd.concat([train_data, test_data])


    # Apply the attack mapping to the dataset
    data['attack'] = data['attack'].map(ATTACK_MAPPING)

    return data



def encodeLabels(data):
    # Initialize separate LabelEncoders for each categorical column
    protocol_le = LabelEncoder()
    service_le = LabelEncoder()
    flag_le = LabelEncoder()
    attack_le = LabelEncoder()

    # Encode categorical features individually
    data['protocol_type'] = protocol_le.fit_transform(data['protocol_type'])
    data['service'] = service_le.fit_transform(data['service'])
    data['flag'] = flag_le.fit_transform(data['flag'])
    data['attack'] = attack_le.fit_transform(data['attack'])

    # Save the fitted LabelEncoders
    joblib.dump(protocol_le, PROTOCOL_LE_PATH)
    joblib.dump(service_le, SERVICE_LE_PATH)
    joblib.dump(flag_le, FLAG_LE_PATH)
    joblib.dump(attack_le, ATTACK_LE_PATH)

    # Standardize numerical features
    scaler = StandardScaler()

    # Exclude 'attack' and 'level' from numerical columns since they are the target variables
    numerical_cols = data.columns.drop(['attack', 'level'])
    data[numerical_cols] = scaler.fit_transform(data[numerical_cols])

    # Save the fitted StandardScaler
    joblib.dump(scaler, SCALER_LE_PATH)

    return data





def splitData(data, test_size=0.2, random_state=42):

    X = data.drop(['attack', 'level'], axis=1)
    y = data['attack']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, stratify=y, random_state=random_state)

    return X_train, X_test, y_train, y_test


def trainRandomForestClassifier(X_train, y_train):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    #Save trained RandomForestClassifier model
    joblib.dump(clf, RFC_PATH)

    return clf


def trainXGBoost(X_train, y_train):
    clf = xgb.XGBClassifier(random_state=42)
    clf.fit(X_train, y_train)

    #Save trained XGBoost model
    joblib.dump(clf, XGB_PATH)

    return clf



# Function to map raw TCP flags to the corresponding NSL-KDD labels
def mapTcpFlags(tcp_flags):
    if tcp_flags == 0x02:  # SYN flag only
        return 'S0'
    elif tcp_flags == 0x12:  # SYN + ACK
        return 'S1'
    elif tcp_flags == 0x10:  # ACK flag only
        return 'SF'
    elif tcp_flags == 0x14:  # RST + ACK
        return 'REJ'
    elif tcp_flags == 0x04:  # RST flag only
        return 'RSTO'
    elif tcp_flags == 0x01:  # FIN flag only
        return 'S2'
    elif tcp_flags == 0x11:  # FIN + ACK
        return 'S3'
    elif tcp_flags == 0x40:  # PSH flag only
        return 'OTH'
    elif tcp_flags == 0x18:  # PSH + ACK
        return 'SH'
    else:
        return 'OTH'  # Default case for other or unknown flag combinations



def encodeFeatures(protocol_type, flag, service):
    protocol_type_le = joblib.load(PROTOCOL_LE_PATH)
    service_le = joblib.load(SERVICE_LE_PATH)
    flag_le = joblib.load(FLAG_LE_PATH)

    # Encode protocol_type
    protocol_type_encoded = protocol_type_le.transform([protocol_type])[0] if protocol_type != -1 else -1

    # Encode service
    service_encoded = service_le.transform([service])[0] if service != -1 else -1

    # Encode flag
    flag_encoded = flag_le.transform([flag])[0] if flag != -1 else -1

    return protocol_type_encoded, flag_encoded, service_encoded



def get_my_ip():
    # Get the default gateway (this is usually the gateway for internet traffic)
    gws = ni.gateways()
    default_gateway = gws['default'][ni.AF_INET][1]  # Get the interface associated with the default gateway
    
    try:
        # Get the IP address for the interface used by the default gateway
        iface_details = ni.ifaddresses(default_gateway)
        if ni.AF_INET in iface_details:
            ip_addr = iface_details[ni.AF_INET][0]['addr']
            return default_gateway, ip_addr
    except KeyError:
        return None, None



# Function to extract features from a packet
def extractFeatures(packet):
    global SESSIONS, HOST_STATS

    session_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
    SESSIONS[session_key].append(packet)


    ip_addr = ''
    iface, iface_ip = get_my_ip()

    if iface_ip and packet.haslayer(IP):
        print("Sender : ", packet[IP].src)
        print("Receiver : ", packet[IP].dst)

        if packet[IP].dst == iface_ip:
            # Incoming packet (sender's IP)
            sender_ip = packet[IP].src
            ip_addr = sender_ip
        else:
            # Outgoing packet (receiver's IP)
            receiver_ip = packet[IP].dst
            ip_addr = receiver_ip



    # Get current time
    current_time = time.time()

    # Get destination IP and service
    dst_ip = packet[IP].dst
    service = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 'other'

    # Check if the time window has passed
    if current_time - HOST_STATS[dst_ip]["last_time"] > TIME_WINDOW:
        HOST_STATS[dst_ip]["srv_count"] = 0
        HOST_STATS[dst_ip]["dst_host_count"] = 0
        HOST_STATS[dst_ip]["num_sessions"] = 0

    # Update counts
    HOST_STATS[dst_ip]["srv_count"] += 1
    HOST_STATS[dst_ip]["dst_host_count"] += 1
    HOST_STATS[dst_ip]["num_sessions"] += 1

    # Update the last time this IP was seen
    HOST_STATS[dst_ip]["last_time"] = current_time

    srv_count = HOST_STATS[dst_ip]["srv_count"]
    dst_host_count = HOST_STATS[dst_ip]["dst_host_count"]
    num_sessions = HOST_STATS[dst_ip]["num_sessions"]

    # Feature: duration
    duration = packet.time - SESSIONS[session_key][0].time if SESSIONS[session_key] else 0

    # Debugging Protocol Type
    if packet.haslayer(IP):
        print(f"Protocol: {packet[IP].proto}")
        protocol_type = PROTOCOL_TYPE_MAPPING.get(packet[IP].proto, -1)
    else:
        protocol_type = -1

    # Debugging TCP Flags
    if packet.haslayer(TCP):
        print(f"TCP Flags: {packet[TCP].flags}")
        flag = mapTcpFlags(packet[TCP].flags)
    else:
        flag = 'OTH'

    # Debugging Service (TCP port)
    if packet.haslayer(TCP):
        print(f"TCP Destination Port: {packet[TCP].dport}")
        service = SERVICE_MAPPING.get(packet[TCP].dport, 'other')
        print(f"Service: {service}")
    else:
        service = -1

    # Feature: src_bytes
    src_bytes = len(packet[Raw].load) if packet.haslayer(Raw) else 0

    # Feature: dst_bytes (sum of response packets' lengths in the session)
    dst_bytes = sum(len(p[Raw].load) for p in SESSIONS[session_key] if p.haslayer(Raw)) if packet.haslayer(Raw) else 0

    # Feature: same_srv_rate
    current_time = time.time()
    same_srv_rate = HOST_STATS[packet[IP].dst]["srv_count"] / len(SESSIONS[session_key]) if SESSIONS[session_key] else 0

    # Feature: diff_srv_rate
    if current_time - HOST_STATS[packet[IP].dst]["last_time"] > TIME_WINDOW:
        HOST_STATS[packet[IP].dst]["diff_srv_count"] = 0
    HOST_STATS[packet[IP].dst]["diff_srv_count"] += 1
    diff_srv_rate = HOST_STATS[packet[IP].dst]["diff_srv_count"] / len(SESSIONS) if SESSIONS else 0

    # Feature: serror_rate
    serror_rate = sum(1 for p in SESSIONS[session_key] if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(SESSIONS[session_key]) if SESSIONS[session_key] else 0

    # Feature: rerror_rate
    rerror_rate = sum(1 for p in SESSIONS[session_key] if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(SESSIONS[session_key]) if SESSIONS[session_key] else 0

    # Feature: srv_serror_rate (SYN errors across all SESSIONS)
    srv_serror_rate = sum(1 for s in SESSIONS.values() for p in s if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(SESSIONS[session_key]) if SESSIONS else 0

    # Feature: srv_rerror_rate (RST errors across all SESSIONS)
    srv_rerror_rate = sum(1 for s in SESSIONS.values() for p in s if p.haslayer(TCP) and p[TCP].flags & 0x04) / len(SESSIONS[session_key]) if SESSIONS else 0

    # Feature: srv_diff_host_rate
    srv_diff_host_count = HOST_STATS[packet[IP].dst]["srv_diff_host_count"]
    srv_count = HOST_STATS[packet[IP].dst]["srv_count"]
    srv_diff_host_rate = srv_diff_host_count / srv_count if srv_count else 0

    # Feature: dst_host_srv_rerror_rate
    dst_host_srv_rerror_rate = HOST_STATS[packet[IP].dst]["rerror_count"] / HOST_STATS[packet[IP].dst]["srv_count"] if HOST_STATS[packet[IP].dst]["srv_count"] else 0

    # Feature: dst_host_srv_diff_host_rate
    dst_host_srv_diff_host_rate = HOST_STATS[packet[IP].dst]["diff_srv_count"] / HOST_STATS[packet[IP].dst]["srv_count"] if HOST_STATS[packet[IP].dst]["srv_count"] else 0

    # Feature: dst_host_srv_serror_rate
    dst_host_srv_serror_rate = HOST_STATS[packet[IP].dst]["srv_error"] / HOST_STATS[packet[IP].dst]["srv_count"] if HOST_STATS[packet[IP].dst]["srv_count"] else 0

    # Feature: dst_host_diff_srv_rate
    dst_host_diff_srv_rate = HOST_STATS[packet[IP].dst]["diff_srv_count"] / len(SESSIONS) if SESSIONS else 0

    # Feature: dst_host_same_srv_rate
    dst_host_same_srv_rate = HOST_STATS[packet[IP].dst]["srv_count"] / len(SESSIONS) if SESSIONS else 0

    # Feature: dst_host_same_src_port_rate
    dst_host_same_src_port_rate = HOST_STATS[packet[IP].dst]["same_src_port_count"] / HOST_STATS[packet[IP].dst]["srv_count"] if HOST_STATS[packet[IP].dst]["srv_count"] else 0

    # Feature: dst_host_serror_rate
    dst_host_srv_count = HOST_STATS[packet[IP].dst]["srv_count"]
    dst_host_srv_error = HOST_STATS[packet[IP].dst]["srv_error"]
    dst_host_serror_rate = dst_host_srv_error / dst_host_srv_count if dst_host_srv_count else 0

    # Feature: dst_host_rerror_rate
    dst_host_rerror_rate = HOST_STATS[packet[IP].dst]["rerror_count"] / len(SESSIONS) if SESSIONS else 0

    # Feature: count (number of connections in the time window)
    count = len(SESSIONS[session_key])

    # Feature: wrong_fragment
    wrong_fragment = packet[IP].frag if packet.haslayer(IP) else 0

    # Feature: is_host_login
    is_host_login = 1 if packet[IP].src == packet[IP].dst else 0

    # Feature: land
    land = 1 if (packet[IP].src == packet[IP].dst and packet.haslayer(TCP) and packet[TCP].sport == packet[TCP].dport) else 0

    # Feature: urgent
    urgent = packet[TCP].urgptr if packet.haslayer(TCP) else 0

    # Placeholder values for other features
    num_failed_logins = 0
    is_guest_login = 0
    hot = 0
    root_shell = 0
    logged_in = 0
    num_compromised = 0
    su_attempted = 0
    num_root = 0
    num_file_creations = 0
    num_shells = 0
    num_access_files = 0
    num_outbound_cmds = 0


    # The rest of the feature extraction code...
    feature_vector = [
        duration, protocol_type, service, flag, src_bytes, dst_bytes,
        land, wrong_fragment, urgent, hot, num_failed_logins,
        logged_in, num_compromised, root_shell, su_attempted, num_root,
        num_file_creations, num_shells, num_access_files, num_outbound_cmds,
        is_host_login, is_guest_login, count, srv_count, serror_rate,
        srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
        diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count,
        dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate,
        dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate,
        dst_host_rerror_rate, dst_host_srv_rerror_rate, ip_addr
    ]


    return feature_vector 




def writePacketToCSV(feature_vector, attack_type, csv_filename=PACKETS_CSV_PATH):
    global FEATURE_NAMES

    # Check if the file exists
    file_exists = os.path.isfile(csv_filename)
    columns = FEATURE_NAMES + ['ip_addr', 'attack_type', 'date_time']
    # Open CSV file in append mode
    with open(csv_filename, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)

        # Write the header if the file is new
        if not file_exists:
            writer.writeheader()

        # Write the packet details
        writer.writerow(dict(zip(columns, feature_vector + [attack_type, datetime.now()])) )



# Function to predict the class of a packet
def predictPacketClass(feature_vector_encoded):
    global ENGINE, FEATURE_NAMES, ATTACK_NAMES

    scaler = joblib.load(SCALER_LE_PATH)

    if ENGINE == 'XGBoost':
        clf = joblib.load(XGB_PATH)
    
    elif ENGINE == 'RandomForestClassifier':
        clf = joblib.load(RFC_PATH)


    # Create a DataFrame from the feature vector
    feature_df = pd.DataFrame([feature_vector_encoded], columns=FEATURE_NAMES)

    # Scale features
    feature_vector_scaled = scaler.transform(feature_df)

    prediction = clf.predict(feature_vector_scaled)
    attack_type = ATTACK_NAMES.get(prediction[0], 'Unknown')
    return attack_type






def capturePackets(interface=None):
    global START_TIME
    START_TIME = datetime.now()

    if not interface:
        interface = conf.iface

    def processPacket(packet):
        try:
            feature_vector = extractFeatures(packet)

            feature_vector_encoded = feature_vector[:-1]
            # Encode the labels
            protocol_type_encoded, flag_encoded, service_encoded = encodeFeatures(feature_vector[1], feature_vector[3], feature_vector[2])

            feature_vector_encoded[1] = protocol_type_encoded
            feature_vector_encoded[3] = flag_encoded
            feature_vector_encoded[2] = service_encoded

            # Predict the class of the packet
            attack_type = predictPacketClass(feature_vector_encoded)

            print(f"Packet classified as: {attack_type}\n")

            # Write the packet details to the CSV file
            writePacketToCSV(feature_vector, attack_type)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def packet_capture_loop():
        global STOP_FLAG
        sniff(iface=interface, prn=processPacket, stop_filter=lambda x: STOP_FLAG)
    
    packet_capture_loop()








def getCounts(csv_filename):
    df = pd.read_csv(csv_filename)
    attack_counts = df['attack_type'].value_counts()
    return attack_counts.to_dict()


def getAttackDetails(csv_filename):

    df = pd.read_csv(csv_filename)
    filtered_df = df[df['attack_type'] != 'Normal']
    result_df = filtered_df[['date_time', 'attack_type', 'ip_addr']]
    
    return result_df.to_dict(orient='records')



def analyzeStatus(csv_filename):
    # Define thresholds for risk levels
    RISK_THRESHOLDS = {
        "Protected": 0,
        "Low Risk": {
            'Probe': 20,
            'R2L': 25
        },
        "Medium Risk": {
            'Probe': 30,
            'R2L': 35
        },
        "High Risk": {
            'Probe': 40,
            'R2L': 45
        },
        "Critical": {
            'Probe': 50,
            'R2L': 55,
            'DoS': 20,
            'U2R': 20
        }
    }

    # Analyze the CSV file
    attack_counts = getCounts(csv_filename)
    total_attacks = sum(attack_counts.values())

    if total_attacks == 0:
        return "Protected"  # Avoid division by zero

    # Calculate the percentage of each attack type
    attack_percentages = {attack: (count / total_attacks) * 100 for attack, count in attack_counts.items()}

    # Check for specific critical attack types
    if (attack_percentages.get('DoS', 0) > RISK_THRESHOLDS['Critical']['DoS'] or
        attack_percentages.get('U2R', 0) > RISK_THRESHOLDS['Critical']['U2R']):
        return "Critical"

    # Determine the risk status based on percentages in predefined order
    if any(attack_percentages.get(attack, 0) > threshold for attack, threshold in RISK_THRESHOLDS['Critical'].items()):
        return "Critical"
    elif any(attack_percentages.get(attack, 0) > threshold for attack, threshold in RISK_THRESHOLDS['High Risk'].items()):
        return "High Risk"
    elif any(attack_percentages.get(attack, 0) > threshold for attack, threshold in RISK_THRESHOLDS['Medium Risk'].items()):
        return "Medium Risk"
    elif any(attack_percentages.get(attack, 0) > threshold for attack, threshold in RISK_THRESHOLDS['Low Risk'].items()):
        return "Low Risk"

    return "Protected"


def analyze(csv_filename=PACKETS_CSV_PATH):
    counts = getCounts(csv_filename)
    status = analyzeStatus(csv_filename)
    attack_details = getAttackDetails(csv_filename)
    print(status)

    analyze_details = {'status':status, 'counts':counts, "attack_details" : attack_details}
    return analyze_details




def saveScanRecords():
    global PACKETS_CSV_PATH, START_TIME, STOP_TIME

    STOP_TIME = datetime.now()

    csv_filename = PACKETS_CSV_PATH

    # Format STOP_TIME to 'yyyy-mm-dd_hh-mm-ss'
    formatted_time = STOP_TIME.strftime('%Y-%m-%d_%H-%M-%S')
    new_csv_filename = os.path.join(settings.STATICFILES_DIRS[0], 'capture_history', f'{formatted_time}.csv')

    # Analyze the CSV file to determine the status
    analyze_details = analyze(csv_filename)
    status = analyze_details['status']
    
    # Rename the CSV file
    os.rename(csv_filename, new_csv_filename)

    # Save the details to the ScanRecord table
    # scan_record = ScanRecord(
    #     start_time=START_TIME,
    #     stop_time=STOP_TIME,
    #     status=status,
    #     csv_filename=new_csv_filename,
    #     user=None  # Replace with the actual user if needed
    # )
    # scan_record.save()




def set_stop_flag(value):
    global STOP_FLAG
    STOP_FLAG = value

    





# data = setupDataset()

# data = encodeLabels(data)

# X_train, X_test, y_train, y_test = splitData(data)

# clf = trainXGBoost(X_train, y_train)

# capturePackets()