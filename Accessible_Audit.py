# Group: TwoSHA2
# Author: Thomas Thibaut, Isaac Beagle, Carson Wilber
# File: Accessible_Audit.py
# Desc: Perform a system audit
from tkinter import *
from datetime import datetime
import ipaddress
import subprocess
import json
from AA_Constants import *
from AA_Reports import generate_report

# GLOBAL VARIABLES
tkinter_window_width = 640
tkinter_window_height = 480


# Run a bash command as if it were in the User's shell.
# Return: A string with the bash output.
def run_bash_command(command):
    return str(subprocess.Popen(["/usr/bin/env", "bash", "-c", command], stdout=subprocess.PIPE).communicate()[0]) \
        .lstrip().rstrip().lstrip("b'").rstrip("\'").split("\\n")


# Output supplied data to a text file in JSON (RFC4627) format
def output_to_json(filename, metadata, dataset):
    # Open file for writing
    file = open(filename, "w")

    # If a trailing null was passed with the command output, remove it.
    if '' in dataset:
        dataset.remove('')

    # Insert opening brackets and filename
    file.writelines("{\n\t\"%s\": [" % filename)

    # Iterate through elements...
    for element in dataset:

        # Create a Dictionary object from the metadata header and line of output and parse the dictionary to JSON
        output = (json.dumps(dict(zip(metadata, element.split())), indent=4))

        # Append a comma to separate elements, except on the last element.
        if element != dataset[-1]:
            output += ","

        # Write the JSON element to the file.
        file.writelines(output)

    # Insert closing brackets
    file.writelines("\n]\n}\n")
    file.close()


# Output supplied dictionary to a text file in JSON format
def export_to_json2(filename, dictionary):
    # Open file for writing
    file = open(filename, "w")

    # Insert opening brackets and filename
    file.writelines("{\n\t\"%s\": [" % filename)

    # Insert an open bracket, so the data can be parse as a list
    file.writelines(json.dumps(dictionary, indent=4))

    # Insert closing brackets.
    file.writelines("\n]\n}\n")
    file.close()


# Display a popup to the user
def build_popup(title, message):
    # Create a popup window object
    message_window = Toplevel()
    message_window.geometry("%dx%d" % (tkinter_window_width / 1.5, tkinter_window_height / 1.5))

    # Assign title to window
    message_window.title = title

    # Assign the message to a label object
    message_label = Label(master=message_window, text=message)

    # Create a button that closes the window
    message_button = Button(master=message_window, text="Close", command=lambda: message_window.destroy())

    # Place elements
    message_label.place(relx=0.5, rely=0.30, anchor=CENTER)
    message_button.place(relx=0.5, rely=0.65, anchor=CENTER)

    # Display Window
    message_window.mainloop()


# Display a popup to the user
def build_popup_score(title, message, letter_grade, message2):
    # Create a popup window object
    message_window = Toplevel()
    message_window.geometry("%dx%d" % (tkinter_window_width / 1.5, tkinter_window_height / 1.5))

    # Assign title to window
    message_window.title = title

    # Assign the message to a label object
    message_label = Label(master=message_window, text=message)
    message_label2 = Label(master=message_window, text=message2)
    score_label = Label(master=message_window, text=letter_grade)
    score_label.config(font=("TkDefaultFont", 32))

    # Create a button that closes the window
    message_button = Button(master=message_window, text="Close", command=lambda: message_window.destroy())

    # Place elements
    message_label.place(relx=0.5, rely=0.10, anchor=CENTER)
    message_button.place(relx=0.5, rely=0.50, anchor=CENTER)
    message_label2.place(relx=0.5, rely=0.80, anchor=CENTER)
    score_label.place(relx=0.5, rely=0.30, anchor=CENTER)

    # Display Window
    message_window.mainloop()


def build_gui():
    # Build Window
    root = Tk()
    root.geometry("%dx%d" % (tkinter_window_width, tkinter_window_height))
    root.title("Accessible Audit")

    # Create Main Page
    label_welcome_message = Label(text="Welcome to Accessible Audit!\n"
                                       "Our mission is to provide our users with an\n"
                                       " easy-to-understand, yet comprehensive security audit.\n\n"
                                       "Our work is simple, free, and most importantly, open-source.\n"
                                       "Click the button below to begin!\n")

    # Welcome Message
    label_welcome_message.place(relx=0.5, rely=0.35, anchor=CENTER)

    # Buttons
    button_run_audit = Button(root, text='Audit my system!', command=lambda: run_audit(root))
    button_run_audit.place(relx=0.5, rely=0.65, anchor=CENTER)

    # Display Window
    root.mainloop()


# Gather network information about open/listening ports on the system.
def perform_network_scan():
    # Bash Commands
    command_get_network_information = "lsof -i | grep LISTEN 2>&1"

    # Run the bash commands.
    network_output = run_bash_command(command_get_network_information)

    # Prepare JSON Metadata for export.
    json_metadata = ['command', 'PID', 'USER', 'FD', 'TYPE', 'DEVICE', 'SIZE/OF', 'NODE', 'NAME']

    # Write data to file.
    output_to_json(file_path_network, json_metadata, network_output)

    return network_output


# Gather information about password files that could be on the user's system.
def perform_password_scan():
    # Bash command
    command_get_suspect_password_files = 'grep --exclude-dir=".*" --exclude={"*.py",".*"} -Ilrn "/home/$(logname)" -e ' \
                                         '"password" '

    # Run bash command and parse output.
    suspect_files = run_bash_command(command_get_suspect_password_files)

    # Prepare the JSON Metadata for export.
    json_metadata = ["filename:"]

    # Write data to file.
    output_to_json(file_path_password, json_metadata, suspect_files)

    return suspect_files


# Gather information about running services.
def perform_service_scan():
    # Bash command
    command_get_unknown_services = 'sudo service --status-all 2>&1'

    # Run bash command and parse output
    services = run_bash_command(command_get_unknown_services)

    # Clean up the output of the bash command by constructing a new list, parsing the raw bash output, and passing it
    # to the new list.
    services_json_ready = []
    for service in services:
        if service != '':
            services_json_ready.append(service.lstrip(" [ ").replace(" ] ", ""))

    # Prepare the JSON Metadata for export.
    json_metadata = ["status", "service"]

    # Write data to file
    output_to_json(file_path_services, json_metadata, services_json_ready)

    return services_json_ready


# Gather password expiry information
def perform_password_expiry_scan():
    # Bash command
    command_get_password_expiry = 'sudo chage -l $(logname)'

    # Run bash command and parse output
    password_expiry = run_bash_command(command_get_password_expiry)

    # Construct new array and clean the data into a usable format
    password_expiry_header = []
    password_expiry_data = []
    for element in password_expiry:
        if element != '':
            current_element = element.split(": ")
            password_expiry_header.append(current_element[0].replace(" ", "_").replace("\\t", ""))
            password_expiry_data.append(current_element[1].replace(" ", "_").replace(",", ""))

    export_to_json2(file_path_password_policy, dict(zip(password_expiry_header, password_expiry_data)))

    return password_expiry_data


# Gather NIC information
def perform_network_card_gather():
    # Bash command
    command_get_network_card_data = run_bash_command("hostname -I")

    # Split the addresses into iterable elements
    ip_addresses = []
    for element in list(filter(None, command_get_network_card_data)):
        ip_addresses = element.split()

    # Gather the IP addresses from bash command.
    json_header = ["IP"]

    output_to_json(file_path_network_card, json_header, ip_addresses)

    return ip_addresses


# Load a json-formatted report
def load_json_file(filename):
    with open(filename) as file:
        data = json.loads(file.read())
    return data


def get_network_score():
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


def get_network_card_score():
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


def get_password_score():
    password_suspect_report = load_json_file(file_path_password)

    return 100 / (len(password_suspect_report[file_path_password]) + 1)


def get_password_policy_score():
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


def get_service_score():
    service_report = load_json_file(file_path_services)
    known_services = []

    for element in service_report[file_path_services]:
        if element['status'] != '?':
            known_services.append(element)

    return 100 - (len(service_report[file_path_services]) - len(known_services)) / len(
        service_report[file_path_services])


# Generate the user's score based on each report
def generate_score():
    number_of_tests = 5
    network_score = get_network_score()
    network_card_score = get_network_card_score()
    password_score = get_password_score()
    password_policy_score = get_password_policy_score()
    service_score = get_service_score()
    return (
                       network_score + network_card_score + password_score + password_policy_score + service_score) / number_of_tests


# Display message when scan is complete.
def display_score(score):
    # Calculate Letter Grade
    if score >= 90:
        letter_grade = 'A'
    elif 90 > score >= 80:
        letter_grade = 'B'
    elif 80 > score >= 70:
        letter_grade = 'C'
    elif 70 > score >= 60:
        letter_grade = 'D'
    else:
        letter_grade = 'F'

    score_report_title = "Score Report"
    score_report_message1 = "Your overall security score is:"
    score_report_message2 = "To see a more detailed breakdown of your grade,\nview the " \
                            "full report on your desktop.\n\nThanks for using Accessible Audit!"

    build_popup_score(score_report_title, score_report_message1, letter_grade, score_report_message2)


# Display the 'scan in progress' message.
def display_loading_message(root):
    # Display message when starting scan
    label_loading = Label(text="Scan is running. Stay tuned!")
    label_loading.place(relx=0.5, rely=0.80, anchor=CENTER)

    # Refresh the application
    root.update()

    return label_loading


# Display the 'scan is finished' message.
def display_completion_message(root, label_loading):
    # Display message when scan is completed
    label_loading.place_forget()
    label_loading = Label(text="Scan complete!")
    label_loading.place(relx=0.5, rely=0.80, anchor=CENTER)
    root.update()


def run_audit(root):
    # Display the 'scan in progress' message.
    label_loading = display_loading_message(root)

    # Make sure a directory exists,
    run_bash_command("sudo mkdir -p /var/log/audit")

    # Gather information about listening network sockets on the machine.
    network_scan_result = perform_network_scan()

    # Scan the home directory for files containing password information.
    password_scan_result = perform_password_scan()

    # Gather information about running services.
    service_scan_result = perform_service_scan()

    # Gather password expiration data
    password_expiry_scan_result = perform_password_expiry_scan()

    # Ensure that user is using an IP address in private network space.
    network_card_gather_result = perform_network_card_gather()

    # Display the 'scan is finished' message.
    display_completion_message(root, label_loading)

    # Generate score
    score = int(generate_score())

    # Generate a report with the results.
    generate_report(file_path_audit_directory, **{
        audit_type_network: network_scan_result,
        audit_type_password: password_scan_result,
        audit_type_services: service_scan_result,
        audit_type_password_policy: password_expiry_scan_result,
        audit_type_network_card: network_card_gather_result
    })

    # Display the score window.
    display_score(score)


def main():
    build_gui()


# Call main()
if __name__ == "__main__":
    main()
