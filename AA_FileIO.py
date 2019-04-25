import json

# Load a json-formatted report
def load_json_file(filename):
    with open(filename) as file:
        data = json.loads(file.read())
    return data


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
