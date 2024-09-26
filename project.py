import csv
import logging
import time
from collections import defaultdict

# Set up logging configuration
logging.basicConfig(level=logging.ERROR, filename='error.log')

# Define protocol mapping
protocol_mapping = {
    '6': 'tcp',   # TCP
    '17': 'udp',  # UDP
    '1': 'icmp',  # ICMP
    '47': 'gre',  # GRE
    '2': 'igmp',  # IGMP
    '89': 'ospf',  # OSPF
    '4': 'ipip',  # IP in IP
}

# Function to load the lookup table into a dictionary for fast lookup
def load_lookup_table(filename):
    lookup_dict = defaultdict(list) 
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            port_protocol = (row['dstport'].strip(), row['protocol'].strip().lower()) 
            lookup_dict[port_protocol].append(row['tag'].strip())  
    return lookup_dict

# Function to process flow logs efficiently
def process_flow_logs(log_filename, lookup_dict):
    tag_count = defaultdict(int)
    port_protocol_count = defaultdict(int)
    untagged_count = 0
    untagged_flows = []  
    batch_size = 10000  

    def process_line(line):
        nonlocal untagged_count
        try:
            parts = line.split()
            if len(parts) < 13:
                logging.error(f"Malformed line (missing fields): {line.strip()}")
                return

            dstport = parts[6].strip()
            protocol_number = parts[7].strip()
            protocol = protocol_mapping.get(protocol_number, 'unknown')
            
            if protocol == 'unknown':
                logging.warning(f"Unrecognized protocol number: {protocol_number} in line: {line.strip()}")

            port_protocol_key = (dstport, protocol)
            port_protocol_count[port_protocol_key] += 1

            if port_protocol_key in lookup_dict:
                tag = lookup_dict[port_protocol_key][0]
                tag_count[tag] += 1
            else:
                untagged_count += 1
                untagged_flows.append((dstport, protocol))

        except Exception as e:
            logging.error(f"Error processing line: {line.strip()} - {e}")

    # Reading large log files in batches to optimize memory usage
    with open(log_filename, 'r') as logfile:
        batch = []
        for i, line in enumerate(logfile):
            batch.append(line)
            if i % batch_size == 0 and i > 0:
                for log_line in batch:
                    process_line(log_line)
                batch = []  # Clear batch

        # Process any remaining lines
        for log_line in batch:
            process_line(log_line)

    return tag_count, port_protocol_count, untagged_count, untagged_flows

# Function to write the output to CSV files
def write_output(tag_count, port_protocol_count, untagged_count, untagged_flows):
    # Output for Tag Counts
    with open('tag_counts.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Tag', 'Count'])
        for tag, count in tag_count.items():
            writer.writerow([tag, count])
        writer.writerow(['Untagged', untagged_count])

    # Output for Port/Protocol Counts
    with open('port_protocol_counts.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Destination Port', 'Protocol', 'Count'])
        for (port, protocol), count in port_protocol_count.items():
            writer.writerow([port, protocol, count])

    # Output for Untagged Flows
    with open('untagged_flows.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Destination Port', 'Protocol'])
        for dstport, protocol in untagged_flows:
            writer.writerow([dstport, protocol])

    # Output summary to output.csv in a proper format
    with open('output.csv', 'w', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerow(['Summary of Flow Log Processing'])
        writer.writerow([''])
        
        writer.writerow(['Tag Counts'])
        for tag, count in tag_count.items():
            writer.writerow([tag, count])
        writer.writerow(['Untagged', untagged_count])
        writer.writerow([''])

        writer.writerow(['Port/Protocol Counts'])
        for (port, protocol), count in port_protocol_count.items():
            writer.writerow([port, protocol, count])

        writer.writerow([''])
        writer.writerow(['Untagged Flows'])
        for dstport, protocol in untagged_flows:
            writer.writerow([dstport, protocol])

# Main function to execute the program
def main():
    lookup_filename = 'lookup_table.csv'  # Name of the lookup table file
    flow_log_filename = 'flow_logs.txt'  # Name of the flow log file

    # Load the lookup table
    lookup_dict = load_lookup_table(lookup_filename)

    # Measure processing time
    start_time = time.time()

    # Process the flow logs and get counts
    tag_count, port_protocol_count, untagged_count, untagged_flows = process_flow_logs(flow_log_filename, lookup_dict)

    # Write the output to CSV files and output.csv
    write_output(tag_count, port_protocol_count, untagged_count, untagged_flows)

    end_time = time.time()
    print(f"Processing time: {end_time - start_time:.2f} seconds")  # Display processing time

if __name__ == "__main__":
    main()
