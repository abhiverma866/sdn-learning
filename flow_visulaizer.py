import re
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tabulate import tabulate

# ---------- Protocol-Based Flow Parser ----------
def parse_flows(flow_text):
    flow_entries = flow_text.strip().split('\n')
    flow_table = []

    for entry in flow_entries:
        protocol = 'Unknown'
        type_desc = ''
        in_port = re.search(r'in_port="?([^",]+)"?', entry)
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
        actions = re.search(r'actions=output:"?([^"]+)"?', entry)
        n_packets = re.search(r'n_packets=(\d+)', entry)

        if 'icmp' in entry:
            protocol = 'ICMP'
            if icmp_type:
                icmp_map = {'8': 'Echo Request', '0': 'Echo Reply'}
                type_desc = icmp_map.get(icmp_type.group(1), f"ICMP Type {icmp_type.group(1)}")
        elif 'arp' in entry:
            protocol = 'ARP'
            if arp_op:
                arp_map = {'1': 'ARP Request', '2': 'ARP Reply'}
                type_desc = arp_map.get(arp_op.group(1), f"ARP Op {arp_op.group(1)}")
        elif 'tcp' in entry:
            protocol = 'TCP'
            if tp_src and tp_dst:
                type_desc = f"TCP {tp_src.group(1)} → {tp_dst.group(1)}"
            else:
                type_desc = "TCP Flow"
        elif 'udp' in entry:
            protocol = 'UDP'
            if tp_src and tp_dst:
                type_desc = f"UDP {tp_src.group(1)} → {tp_dst.group(1)}"
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

# ---------- OpenFlow Table Parser and Display ----------
def display_openflow_table(flow_text):
    flow_entries = flow_text.strip().split('\n')
    flow_table = []

    for entry in flow_entries:
        # Try to find actions field (may be missing)
        actions_match = re.search(r'actions=([^,\n]+)', entry)
        actions = actions_match.group(1) if actions_match else 'None'

        n_packets_match = re.search(r'n_packets=(\d+)', entry)
        n_packets = n_packets_match.group(1) if n_packets_match else '0'

        n_bytes_match = re.search(r'n_bytes=(\d+)', entry)
        n_bytes = n_bytes_match.group(1) if n_bytes_match else '0'

        priority_match = re.search(r'priority=(\d+)', entry)
        priority = priority_match.group(1) if priority_match else '0'

        idle_timeout_match = re.search(r'idle_timeout=(\d+)', entry)
        idle_timeout = idle_timeout_match.group(1) if idle_timeout_match else None

        hard_timeout_match = re.search(r'hard_timeout=(\d+)', entry)
        hard_timeout = hard_timeout_match.group(1) if hard_timeout_match else None

        if 'actions=' in entry:
            match_part = entry.split('actions=')[0]
        else:
            match_part = entry

        #print("Match part:", repr(match_part))  # DEBUG

        # Try with empty excluded keys for debugging
        excluded_keys = set()

        match_items = re.findall(r'(\w+)=("[^"]+"|\S+)', match_part)

        #print("All extracted pairs:", match_items)  # DEBUG

        match_fields = []
        for k, v in match_items:
            if k not in excluded_keys:
                v_clean = v.strip('"')
                match_fields.append(f"{k}={v_clean}")

        match_str = ', '.join(match_fields) if match_fields else 'None'
        #print("Match string:", match_str)  # DEBUG


        timeout_str = ''
        if idle_timeout:
            timeout_str += f'idle={idle_timeout}s'
        if hard_timeout:
            if timeout_str:
                timeout_str += ', '
            timeout_str += f'hard={hard_timeout}s'
        if not timeout_str:
            timeout_str = 'None'

        counter_str = f"packets={n_packets}, bytes={n_bytes}"

        flow_table.append([
            match_str,
            actions,
            counter_str,
            priority,
            timeout_str
        ])

    # Display the table (same as before)
    table_win = tk.Toplevel()
    table_win.title("OpenFlow Flow Table")
    table_win.geometry("1100x600")

    title_label = tk.Label(table_win, text="OpenFlow Table", font=("Helvetica", 16, "bold"))
    title_label.pack(pady=(10,5))

    total_flows = len(flow_table)
    total_label = tk.Label(table_win, text=f"Total Flows: {total_flows}",
                           font=("Helvetica", 12, "bold"), fg="blue")
    total_label.pack(pady=(0,10))

    headers = ["Match", "Action", "Counter", "Priority", "Timeout"]
    table_str = tabulate(flow_table, headers=headers, tablefmt="fancy_grid")

    # Scrollbars for text widget
    x_scrollbar = tk.Scrollbar(table_win, orient=tk.HORIZONTAL)
    x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
    y_scrollbar = tk.Scrollbar(table_win, orient=tk.VERTICAL)
    y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_area = tk.Text(table_win, wrap=tk.NONE, font=("Courier New", 11), width=140, height=30,
                        xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set)
    text_area.insert(tk.END, table_str)
    text_area.config(state='disabled')
    text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    x_scrollbar.config(command=text_area.xview)
    y_scrollbar.config(command=text_area.yview)


# ---------- Protocol View Display ----------
def display_protocol_table(flow_table):
    table_win = tk.Toplevel()
    table_win.title("Parsed Flow Table (Protocol View)")
    table_win.geometry("1100x600")

    title_label = tk.Label(table_win, text="Flow Table (Protocol View)", font=("Helvetica", 16, "bold"))
    title_label.pack(pady=(10, 5))

    total_flows = len(flow_table)
    total_label = tk.Label(table_win, text="Total Flows: {}".format(total_flows),
                           font=("Helvetica", 12, "bold"), fg="blue")
    total_label.pack(pady=(0, 10))

    headers = ["Protocol", "Type", "In Port", "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Out Port", "Packets"]
    table_str = tabulate(flow_table, headers=headers, tablefmt="fancy_grid")

    # Scrollable text area with horizontal scroll
    frame = tk.Frame(table_win)
    frame.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

    x_scrollbar = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
    x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

    y_scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
    y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_area = tk.Text(frame, wrap=tk.NONE, font=("Courier New", 11),
                        width=160, height=30, xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set)
    text_area.insert(tk.INSERT, table_str)
    text_area.configure(state='disabled')
    text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    x_scrollbar.config(command=text_area.xview)
    y_scrollbar.config(command=text_area.yview)

# ---------- Button Event ----------
def on_parse_button():
    flow_text = input_box.get("1.0", tk.END).strip()
    if not flow_text:
        messagebox.showwarning("No Input", "Please enter flow entries.")
        return

    try:
        protocol_flow_table = parse_flows(flow_text)
        if not protocol_flow_table:
            messagebox.showinfo("No Flows", "No valid flows parsed.")
            return

        display_protocol_table(protocol_flow_table)
        display_openflow_table(flow_text)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

def clear_input():
    input_box.delete('1.0', tk.END)

# ---------- GUI Setup ----------
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
