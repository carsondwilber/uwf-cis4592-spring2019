# Group: TwoSHA2
# Author: Thomas Thibaut, Isaac Beagle, Carson Wilber
# File: Accessible_Audit.py
# Desc: Perform a system audit

from tkinter import *
from tkinter import ttk
import subprocess
import json

# GLOBAL VARIABLES
tkinter_window_width = 640
tkinter_window_height = 480
file_path_audit_directory = "/var/log/audit/"
file_path_network = file_path_audit_directory + "network"
file_path_password = file_path_audit_directory + "password_suspect"
file_path_services = file_path_audit_directory + "services"
file_path_password_policy = file_path_audit_directory + "password_policy"
file_path_network_card = file_path_audit_directory + "network_card"


# Run a bash command as if it were in the User's shell.
# Return: A string with the bash output.
def run_bash_command(command):
    return str(subprocess.Popen(["/usr/bin/env", "bash", "-c", command], stdout=subprocess.PIPE).communicate()[0]) \
        .lstrip().rstrip().lstrip("b'").rstrip("\'").split("\\n")


# Output supplied data to a text file in JSON format.
def export_to_json(filename, metadata, dataset):

    # Open file for writing
    file = open(filename, "w")

    # Insert an open bracket, so the data can be parse as a list
    file.writelines("[\n")

    # Combine the metadata and data list, and "pretty print" them to a file.
    for element in dataset:
        if element != '':
            file.writelines(json.dumps((dict(zip(metadata, element.split()))), indent=4))
            file.writelines("\n")

    # Insert the closing bracket.
    file.writelines("]\n")

    # Close the file.
    file.close()


# Output supplied dictionary to a text file in JSON format
def export_to_json2(filename, dictionary):

    # Open file for writing
    file = open(filename, "w")

    # Insert an open bracket, so the data can be parse as a list
    file.writelines("[\n")
    file.writelines(json.dumps(dictionary, indent=4))

    # Insert the closing bracket.
    file.writelines("\n]\n")

    # Close the file.
    file.close()


def build_gui():

    # Build Window
    root = Tk()
    root.geometry(f"{tkinter_window_width}x{tkinter_window_height}")
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
    button_run_audit = Button(root, text='Audit my system!', command=lambda: begin_audit())
    button_run_audit.place(relx=0.5, rely=0.65, anchor=CENTER)

    # Progress Bar
    progress_bar = ttk.Progressbar()
    progress_bar.place(relx=0.5, rely=0.85, anchor=CENTER)
    progress_bar.place_forget()

    # TODO Figure out how to make a progress bar work.

    # Display Window
    root.mainloop()


# Gather network information about open/listening ports on the system.
def perform_network_scan():

    # Bash Commands
    command_get_network_information = "lsof -i | grep LISTEN"

    # Run the bash commands.
    network_output = run_bash_command(command_get_network_information)

    # Prepare JSON Metadata for export.
    json_metadata = ['command', 'PID', 'USER', 'FD', 'TYPE', 'DEVICE', 'SIZE/OF', 'NODE', 'NAME']

    # Write data to file.
    export_to_json(file_path_network, json_metadata, network_output)


# Gather information about password files that could be on the user's system.
def perform_password_scan():

    # Bash command
    command_get_suspect_password_files = 'grep --exclude-dir=".*" --exclude={"*.py",".*"} -Ilrn "/home/$(logname)" -e '\
                                         '"password" '

    # Run bash command and parse output.
    suspect_files = run_bash_command(command_get_suspect_password_files)

    # Prepare the JSON Metadata for export.
    json_metadata = ["filename:"]

    # Write data to file.
    export_to_json(file_path_password, json_metadata, suspect_files)


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
    export_to_json(file_path_services, json_metadata, services_json_ready)


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
            password_expiry_header.append(current_element[0].replace(" ","_").replace("\\t", ""))
            password_expiry_data.append(current_element[1].replace(" ", "_").replace(",", ""))

    export_to_json2(file_path_password_policy, dict(zip(password_expiry_header, password_expiry_data)))


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

    export_to_json(file_path_network_card,json_header,ip_addresses)


def begin_audit():

    # Make sure a directory exists,
    run_bash_command("sudo mkdir -p /var/log/audit")

    # Gather information about listening network sockets on the machine.
    perform_network_scan()

    # Scan the home directory for files containing password information.
    perform_password_scan()

    # Gather information about running services.
    perform_service_scan()

    # Gather password expiration data
    perform_password_expiry_scan()

    # Ensure that user is using an IP address in private network space.
    perform_network_card_gather()

    # TODO Add the rest of the necessary code here.
    return



def main():
    build_gui()


# Call main()
if __name__ == "__main__":
    main()
