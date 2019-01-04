import argparse
import os

from conf import *
from stat_plot import *


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True, type=str)
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)

    print("[*] config file is {}".format(config_path))
    config_valid, fuzzers_dict, misc_dict = parse_config(config_path)

    if not config_valid:
        print("[!] config: {} is not valid!".format(config_path))
        exit(1)

    generate_plots(fuzzers_dict, misc_dict)


if __name__ == "__main__":
    main()
