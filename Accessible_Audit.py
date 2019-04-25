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
from AA_Scoring import *
from AA_FileIO import *
from AA_Reports import generate_report

# GLOBAL VARIABLES
tkinter_window_width = 640
tkinter_window_height = 480


# Run a bash command as if it were in the User's shell.
# Return: A string with the bash output.
def run_bash_command(command):
    return str(subprocess.Popen(["/usr/bin/env", "bash", "-c", command], stdout=subprocess.PIPE).communicate()[0]) \
        .lstrip().rstrip().lstrip("b'").rstrip("\'").split("\\n")


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

    return (network_output, file_path_network)


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

    return (suspect_files, file_path_password)


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

    return (services_json_ready, file_path_services)


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

    return (password_expiry_data, file_path_password_policy)


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

    return (ip_addresses, file_path_network_card)

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
    #password_scan_result = perform_password_scan()

    # Gather information about running services.
    service_scan_result = perform_service_scan()

    # Gather password expiration data
    password_expiry_scan_result = perform_password_expiry_scan()

    # Ensure that user is using an IP address in private network space.
    network_card_gather_result = perform_network_card_gather()

    # Display the 'scan is finished' message.
    display_completion_message(root, label_loading)

    # Generate score
    score = int(generate_score(file_path_network, file_path_network_card, file_path_password, file_path_password_policy, file_path_services))

    # Generate a report with the results.
    generate_report(file_path_audit_directory, **{
        audit_type_network: network_scan_result,
        #audit_type_password: password_scan_result,
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
