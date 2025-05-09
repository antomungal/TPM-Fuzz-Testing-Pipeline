
import json
import matplotlib.pyplot as plt

def load_stats(file_path="fuzz_results_summary.json"):
    with open(file_path, 'r') as f:
        return json.load(f)

def analyze(stats):
    print("\n===== Fuzzing Results Analysis =====")
    print(f"Total tests: {stats['total_tests']}")
    print("\nResult Frequencies:")
    for result, count in stats['results'].items():
        print(f"  {result}: {count} ({(count / stats['total_tests']) * 100:.2f}%)")

    print("\nQuality Metrics:")
    print(f"  Success rate: {stats['success_rate'] * 100:.2f}%")
    print(f"  Handled error rate: {stats['handled_error_rate'] * 100:.2f}%")
    print(f"  Exception rate: {stats['error_rate'] * 100:.2f}%")

    if stats['error_rate'] > 0.3:
        print("\n[!] Warning: High exception rate detected.")

    if stats['success_rate'] < 0.4:
        print("\n[!] Warning: Low success rate may indicate over-rejection.")

    return stats

def plot_summary(stats):
    labels = list(stats['results'].keys())
    values = list(stats['results'].values())

    plt.figure(figsize=(8, 6))
    plt.bar(labels, values)
    plt.title("Fuzzing Result Distribution")
    plt.xlabel("Result Type")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig("fuzz_analysis_chart.png")
    plt.close()

if __name__ == "__main__":
    stats = load_stats()
    analyzed = analyze(stats)
    plot_summary(analyzed)
