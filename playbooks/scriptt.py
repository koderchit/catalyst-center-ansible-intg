import os
import subprocess
import json
import ast

# Define paths
playbook_dir = "/Users/arcsoni/ansible/dnac/work/collections/ansible_collections/cisco/dnac/playbooks"
log_file = "dnac.log"
hosts_file = "hosts"  # Path to your inventory file

# Function to pretty-print the message
def format_message(msg):
    try:
        # Attempt to parse as JSON
        parsed_msg = json.loads(msg)
        return json.dumps(parsed_msg, indent=4)
    except json.JSONDecodeError:
        try:
            # Attempt to parse as Python dictionary
            parsed_msg = ast.literal_eval(msg)
            return json.dumps(parsed_msg, indent=4)
        except (ValueError, SyntaxError):
            # Return the original message if parsing fails
            return msg

# Clear the log file if it exists
with open(log_file, "w") as log:
    log.write("")  # Clear contents

# Get all playbooks with '_workflow_manager.yml' suffix
playbooks = [
    f for f in os.listdir(playbook_dir)
    if f.endswith("_workflow_manager.yml")
]

if not playbooks:
    print("No playbooks with '_workflow_manager.yml' suffix found.")
    exit(1)

# Iterate over the filtered playbooks
for playbook in playbooks:
    playbook_path = os.path.join(playbook_dir, playbook)
    
    with open(log_file, "a") as log:
        # Write the playbook name to the log file
        log.write(f"### Playbook: {playbook} ###\n")
        
        # Read and write the content of the playbook to the log file
        with open(playbook_path, 'r') as playbook_file:
            playbook_content = playbook_file.read()
            log.write("### Playbook Content ###\n")
            log.write(playbook_content + "\n")
        
        # Run the playbook with inventory and capture output
        process = subprocess.run(
            ["ansible-playbook", "-i", hosts_file, playbook_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Separate the output into lines for formatting
        output_lines = process.stdout.splitlines()
        for line in output_lines:
            if '"msg":' in line or "'msg':" in line:
                # Extract and format the message
                raw_msg = line.split(": ", 1)[1]
                # import epdb
                # epdb.serve(port=9889)
                data_string= raw_msg
                # Extract the part with the dictionary list
                start_index = data_string.find('[', data_string.find('[') + 1)  # Find the second '['
                end_index = data_string.find(']', data_string.find(']') + 1) + 1  # Find the second ']'
                # import epdb
                # epdb.serve(port=9889)
                list_str = data_string[start_index:end_index]  # Extract the list part
                try:
                    if list_str:
                        config_list = ast.literal_eval(list_str)

                        # Pretty print the dictionary
                        a= json.dumps(config_list, indent=4)
                        log.write(a + "\n")
                except:
                    pass
            log.write(line + "\n")
        
        # Add a separator for clarity
        log.write(f"\n--- End of {playbook} ---\n\n")

        print(f"{playbook} Done")

print(f"Selected playbooks executed. Logs saved to {log_file}")
