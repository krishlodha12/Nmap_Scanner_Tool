import nmap
import socket
import logging
from datetime import datetime
from termcolor import colored

# Set up logging
logging.basicConfig(filename='nmap_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def validate_target(target):
    """Validate IP address or domain name."""
    try:
        socket.gethostbyname(target)  # Convert host name to IP, if necessary
        return True
    except socket.error:
        logging.error(f"Invalid target: {target}")
        print(colored(f"Invalid target: {target}. Please enter a valid IP or domain.", 'red'))
        return False

def run_nmap_scan(target, options):
    """Run the Nmap scan and handle errors gracefully."""
    nm = nmap.PortScanner()

    try:
        print(colored(f"\nStarting Nmap scan on {target} with options: {options}", 'cyan'))
        nm.scan(target, arguments=options)

        # If scan succeeded
        logging.info(f"Scan successful on {target}")
        return nm
    except nmap.PortScannerError as e:
        logging.error(f"Nmap error: {e}")
        print(colored(f"Nmap scan failed: {e}", 'red'))
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(colored(f"Unexpected error: {e}", 'red'))
    return None

def display_scan_results(nm, save_to_file=False):
    """Display and format Nmap scan results. Optionally save to a file."""
    if not nm:
        return
    
    result_lines = []

    for host in nm.all_hosts():
        result = f"\nHost: {host} ({nm[host].hostname()})"
        print(colored(result, 'yellow'))
        result_lines.append(result)

        state = f"State: {nm[host].state()}"
        print(colored(state, 'green'))
        result_lines.append(state)

        for protocol in nm[host].all_protocols():
            protocol_info = f"Protocol: {protocol}"
            print(colored(protocol_info, 'blue'))
            result_lines.append(protocol_info)

            port_info = nm[host][protocol]
            for port, state in port_info.items():
                port_state_info = f"Port: {port}\tState: {state}"
                print(f"Port: {colored(port, 'magenta')}\tState: {colored(state, 'green')}")
                result_lines.append(port_state_info)

    if save_to_file:
        filename = f"nmap_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write('\n'.join(result_lines))
        print(colored(f"\nResults saved to {filename}", 'cyan'))

def scan_menu():
    """Interactive menu to choose Nmap scan options."""
    print("\nSelect a scan option:")
    print("1. Regular scan (-sP) [Ping Scan]")
    print("2. Service version detection (-sV)")
    print("3. OS detection (-O)")
    print("4. Full scan (-sS)")
    print("5. Default scan (-sV -sC) [Recommended]")

    choice = input("\nEnter the number corresponding to your choice: ").strip()
    
    scan_options = {
        '1': '-sP',
        '2': '-sV',
        '3': '-O',
        '4': '-sS',
        '5': '-sV -sC'
    }
    
    return scan_options.get(choice, '-sV -sC')  # Default to option 5

def main():
    print(colored("\nWelcome to the Nmap Scanner Tool!", 'cyan', attrs=['bold']))

    # Accept user input for target IP/domain
    target = input(colored("\nEnter target IP address or domain: ", 'yellow')).strip()

    # Validate the target
    if not validate_target(target):
        return

    # Choose scan options from menu
    options = scan_menu()

    # Ask the user if they want to save results
    save_option = input("\nDo you want to save the results to a file? (yes/no): ").strip().lower()
    save_to_file = save_option in ['yes', 'y']

    # Log the scan start time
    logging.info(f"Starting scan on {target}")
    print(colored(f"\nStarting scan on {target} at {datetime.now()}", 'cyan'))

    # Run the scan
    nm = run_nmap_scan(target, options)

    # Display the results
    display_scan_results(nm, save_to_file)

if __name__ == "__main__":
    main()