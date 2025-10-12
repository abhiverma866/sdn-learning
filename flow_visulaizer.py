import re
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tabulate import tabulate

def parse_flows(flow_text):
    flow_entries = flow_text.strip().split('\n')
    flow_table = []

    for entry in flow_entries:
        protocol = 'Unknown'
        type_desc = ''
        in_port = re.search(r'in_port="([^"]+)"', entry)
        dl_src = re.search(r'dl_src=([0-9a-f:]+)', entry)
        dl_dst = re.search(r'dl_dst=([0-9a-f:]+)', entry)
        nw_src = re.search(r'nw_src=([\d\.]+)', entry)
        nw_dst = re.search(r'nw_dst=([\d\.]+)', entry)
        arp_spa = re.search(r'arp_spa=([\d\.]+)', entry)
        arp_tpa = re.search(r'arp_tpa=([\d\.]+)', entry)
        icmp_type = re.search(r'icmp_type=(\d+)', entry)
        arp_op = re.search(r'arp_op=(\d+)', entry)
        tp_src = re.search(r'tp_src=(\d+)', entry)
        tp_dst = re.search(r'tp_dst=(\d+)', entry)
        actions = re.search(r'actions=output:"([^"]+)"', entry)
        n_packets = re.search(r'n_packets=(\d+)', entry)

        if 'icmp' in entry:
            protocol = 'ICMP'
            if icmp_type:
                icmp_map = {'8': 'Echo Request', '0': 'Echo Reply'}
                type_desc = icmp_map.get(icmp_type.group(1), "ICMP Type {}".format(icmp_type.group(1)))
        elif 'arp' in entry:
            protocol = 'ARP'
            if arp_op:
                arp_map = {'1': 'ARP Request', '2': 'ARP Reply'}
                type_desc = arp_map.get(arp_op.group(1), "ARP Op {}".format(arp_op.group(1)))
        elif 'tcp' in entry:
            protocol = 'TCP'
            if tp_src and tp_dst:
                type_desc = "TCP {} → {}".format(tp_src.group(1), tp_dst.group(1))
            else:
                type_desc = "TCP Flow"
        elif 'udp' in entry:
            protocol = 'UDP'
            if tp_src and tp_dst:
                type_desc = "UDP {} → {}".format(tp_src.group(1), tp_dst.group(1))
            else:
                type_desc = "UDP Flow"

        flow_table.append([
            protocol,
            type_desc,
            in_port.group(1) if in_port else '',
            dl_src.group(1) if dl_src else '',
            dl_dst.group(1) if dl_dst else '',
            nw_src.group(1) if nw_src else (arp_spa.group(1) if arp_spa else ''),
            nw_dst.group(1) if nw_dst else (arp_tpa.group(1) if arp_tpa else ''),
            actions.group(1) if actions else '',
            n_packets.group(1) if n_packets else '0'
        ])

    return flow_table

def display_table(flow_table):
    table_win = tk.Toplevel()
    table_win.title("Parsed Flow Table")
    table_win.geometry("1100x600")

    # Title label
    title_label = tk.Label(table_win, text="Flow Table", font=("Helvetica", 16, "bold"))
    title_label.pack(pady=(10,5))

    # Total flows label, centered
    total_flows = len(flow_table)
    total_label = tk.Label(table_win, text="Total Flows: {}".format(total_flows),
                           font=("Helvetica", 12, "bold"), fg="blue")
    total_label.pack(pady=(0,10))

    headers = ["Protocol", "Type", "In Port", "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Out Port", "Packets"]
    table_str = tabulate(flow_table, headers=headers, tablefmt="fancy_grid")

    # ScrolledText for the table with fixed-width font for alignment
    text_area = scrolledtext.ScrolledText(table_win, wrap=tk.NONE, font=("Courier New", 11), width=140, height=30)
    text_area.insert(tk.INSERT, table_str)
    text_area.configure(state='disabled')
    text_area.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

def on_parse_button():
    flow_text = input_box.get("1.0", tk.END).strip()
    if not flow_text:
        messagebox.showwarning("No Input", "Please enter flow entries.")
        return

    try:
        flow_table = parse_flows(flow_text)
        if not flow_table:
            messagebox.showinfo("No Flows", "No valid flows parsed.")
            return

        display_table(flow_table)

    except Exception as e:
        messagebox.showerror("Error", "An error occurred:\n{}".format(str(e)))

def clear_input():
    input_box.delete('1.0', tk.END)

# Main GUI setup
root = tk.Tk()
root.title("OpenFlow Flow Parser")
root.geometry("900x600")

label = ttk.Label(root, text="Enter Flow Entries Below:", font=("Arial", 14))
label.pack(pady=10)

input_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=25, font=("Consolas", 11))
input_box.pack(padx=10, pady=5)

parse_button = ttk.Button(root, text="Parse and Show Table", command=on_parse_button)
parse_button.pack(pady=10)

clear_button = ttk.Button(root, text="Clear Input", command=clear_input)
clear_button.pack(pady=5)

root.mainloop()
