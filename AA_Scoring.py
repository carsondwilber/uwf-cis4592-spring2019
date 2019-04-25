import json
import ipaddress

from AA_FileIO import *

def get_network_score(file_path_network):
    # List of blacklisted ports
    blacklisted_ports = [456, 555, 666, 1001, 1011, 1170, 1234, 1243, 1245, 1492, 1600, 1807, 1981, 2001, 2023, 2115,
                         2140, 2801, 3024, 3129, 3150, 3700, 4092, 4567, 4590, 5000, 5001, 5321, 5400, 5401, 5402, 5569,
                         5742, 6670, 6600, 6771, 6969, 7000, 7300, 7301, 7306, 7307, 7308, 7789, 8787, 9872, 9873, 9874,
                         9875,
                         9989, 10067, 10167, 10607, 11000, 11223, 12223, 12345, 12346, 12361, 12362, 16969, 20001,
                         20034,
                         21544, 22222, 23456, 26274, 30100, 30101, 30102, 31337, 31338, 31339, 31666, 33333, 34324,
                         40412, 40422, 40423, 40426, 47262, 50505, 50766, 53001, 54321, 61466, 65000]

    # Initialize an array for found ports
    found_ports = []

    # Load the network JSON file
    network_report = load_json_file(file_path_network)

    # Loop through the found ports
    for element in network_report[file_path_network]:

        # Using the 'Name' as the key, get the corresponding value
        port = (str(element['NAME']).split(":")[1])

        # If the value is numeric, convert to integer for comparison
        if port.isnumeric():
            port = int(port)
        else:
            continue

        # Append port to list of found ports
        if port in blacklisted_ports and port not in found_ports:
            found_ports.append(port)

    # For each port found, do something with the score
    return (len(blacklisted_ports) - len(found_ports)) / len(blacklisted_ports) * 100


def get_network_card_score(file_path_network_card):
    # Load the NIC JSON file
    network_card_report = load_json_file(file_path_network_card)
    ip_addresses = []
    private_addresses = []

    # Look at each network interface
    for element in network_card_report[file_path_network_card]:

        # Parse IP Addresses. Ignore IPv6
        if ':' not in element['IP']:
            ip_addresses.append(str(element['IP']))

    # Parse for RFC1918
    for element in ip_addresses:
        try:
            ip = ipaddress.IPv4Address(element)
        except ValueError:
            continue

        if ip.is_private:
            private_addresses.append(str(ip))

    return (len(ip_addresses) - len(private_addresses)) / len(ip_addresses) * 100


def get_service_score(file_path_services):
    service_report = load_json_file(file_path_services)
    known_services = []

    for element in service_report[file_path_services]:
        if element['status'] != '?':
            known_services.append(element)

    return 100 - (len(service_report[file_path_services]) - len(known_services)) / len(
        service_report[file_path_services])


def get_password_score(file_path_password):
    password_suspect_report = load_json_file(file_path_password)

    return 100 / (len(password_suspect_report[file_path_password]) + 1)


def get_password_policy_score(file_path_password_policy):
    password_policy_report = load_json_file(file_path_password_policy)
    maximum_number_of_days_between_password_change = ""

    # Determine days since password rotation
    for element in password_policy_report[file_path_password_policy]:
        maximum_number_of_days_between_password_change = element['Maximum_number_of_days_between_password_change']

    # If rotation has been configured, add a point.
    if maximum_number_of_days_between_password_change != "99999":
        return 1
    else:
        return 0


# Generate the user's score based on each report
def generate_score(file_path_network, file_path_network_card, file_path_password, file_path_password_policy, file_path_services):
    number_of_tests = 5
    network_score = get_network_score(file_path_network)
    network_card_score = get_network_card_score(file_path_network_card)
    password_score = get_password_score(file_path_password)
    password_policy_score = get_password_policy_score(file_path_password_policy)
    service_score = get_service_score(file_path_services)
    return (
                       network_score + network_card_score + password_score + password_policy_score + service_score) / number_of_tests
