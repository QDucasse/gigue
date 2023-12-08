import json
import sys


def extract_run_seeds(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    run_seeds = data.get("config_data", {}).get("run_seeds", [])

    # Output the numbers on a single line separated by spaces
    result = ",".join(map(str, run_seeds))
    print(result)


if __name__ == "__main__":
    json_file_path = sys.argv[1]
    extract_run_seeds(json_file_path)
