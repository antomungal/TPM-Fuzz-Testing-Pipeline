# fuzz_tpm.py

import os
import random
import struct
import csv
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter
from tpm_simulator import TPMHandler
import json
import subprocess

CRITICAL_THRESHOLD = 0.3

OUTPUT_CSV = "fuzz_results_log.csv"
OUTPUT_JSON = "fuzz_results_summary.json"
OUTPUT_PNG = "fuzz_results_chart.png"
OUTPUT_ALERT = "fuzz_results_alert.txt"


def mutate_bytes(data, max_mutations=5):
    data = bytearray(data)
    for _ in range(random.randint(1, max_mutations)):
        idx = random.randint(0, len(data) - 1)
        data[idx] = random.randint(0, 255)
    return bytes(data)

def generate_random_command():
    tag = 0x8001
    command_code = 0x0001
    nonce_len = random.randint(0, 64)
    nonce = os.urandom(nonce_len)
    size = 10 + 1 + nonce_len
    header = struct.pack(">H I H", tag, size, command_code)
    body = bytes([nonce_len]) + nonce
    return header + body

def fuzz_tpm(handler, iterations=100, log_file=OUTPUT_CSV):
    with open(log_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Iteration", "Timestamp", "Result", "Error"])
        for i in range(iterations):
            base_cmd = generate_random_command()
            mutated_cmd = mutate_bytes(base_cmd)
            try:
                handler.load_command(mutated_cmd)
                result = handler.handle()
                writer.writerow([i, datetime.utcnow().isoformat(), "Success" if result else "Handled Error", ""])
            except Exception as e:
                writer.writerow([i, datetime.utcnow().isoformat(), "Exception", str(e)])

    summarize_results(log_file)
    run_post_analysis()

def summarize_results(log_file):
    with open(log_file, mode='r') as file:
        reader = csv.DictReader(file)
        results = [row["Result"] for row in reader]

    counts = Counter(results)
    labels = counts.keys()
    values = counts.values()

    # Save bar chart
    plt.figure(figsize=(8, 6))
    plt.bar(labels, values)
    plt.title("TPM Fuzzing Results")
    plt.xlabel("Result Type")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(OUTPUT_PNG)
    plt.close()

    # Save machine-readable summary
    total = sum(counts.values())
    summary = {
        "total_tests": total,
        "results": dict(counts),
        "success_rate": counts.get("Success", 0) / total,
        "error_rate": counts.get("Exception", 0) / total,
        "handled_error_rate": counts.get("Handled Error", 0) / total
    }
    with open(OUTPUT_JSON, "w") as json_file:
        json.dump(summary, json_file, indent=4)

    notify_if_critical(summary)

def notify_if_critical(summary):
    critical_issues = []
    if summary['error_rate'] > CRITICAL_THRESHOLD:
        critical_issues.append("Critically high exception rate detected.")
    if summary['success_rate'] < 1 - CRITICAL_THRESHOLD:
        critical_issues.append("Unusually low success rate detected.")

    if critical_issues:
        print("\n[ALERT] Critical anomalies detected:")
        for issue in critical_issues:
            print(f"  - {issue}")
        with open(OUTPUT_ALERT, "w") as alert_file:
            for issue in critical_issues:
                alert_file.write(issue + "\n")

def run_post_analysis():
    print("\n[Pipeline] Running post-fuzzing analysis...")
    subprocess.run(["python", "analyze_fuzz_stats.py"])

if __name__ == "__main__":
    tpm = TPMHandler()
    fuzz_tpm(tpm, iterations=1000)


