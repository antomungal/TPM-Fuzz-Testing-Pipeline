# TPM-Fuzz-Testing-Pipeline

This repository provides a complete pipeline for fuzz testing Trusted Platform Module (TPM) command handling logic. The system simulates malformed and adversarial command payloads to validate robustness against memory handling flaws such as Out-of-Bounds (OOB) reads and writes.

## Components

### 1. `tpm_simulator.py`

A minimal TPM emulator that:

* Parses TPM commands.
* Verifies buffer sizes.
* Checks nonce structure.
* Simulates basic TPM command flow.

### 2. `fuzz_tpm.py`

Main fuzzing script that:

* Generates randomized and mutated TPM command inputs.
* Logs all outcomes (`Success`, `Handled Error`, `Exception`).
* Summarizes results in CSV, JSON, PNG, and TXT formats.
* Triggers post-analysis automatically.

### 3. `analyze_fuzz_stats.py`

Post-fuzzing analysis module that:

* Reads `fuzz_results_summary.json`.
* Prints structured results.
* Flags high anomaly rates.
* Outputs `fuzz_analysis_chart.png`.

## Outputs

* `fuzz_results_log.csv`: Fuzz execution trace.
* `fuzz_results_summary.json`: Aggregated statistics.
* `fuzz_results_chart.png`: Graphical breakdown of result types.
* `fuzz_results_alert.txt`: Alert log for critical anomaly detection.

## Usage

```bash
python fuzz_tpm.py
```

## Requirements

* Python 3.8+
* `matplotlib`

Install dependencies:

```bash
pip install matplotlib
```

## Notes

* The pipeline includes detection thresholds for high failure rates.
* Ideal for use in CI environments for regression and robustness testing.

## License

MIT License
