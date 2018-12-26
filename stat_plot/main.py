import argparse

from conf import *


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True, type=str)
    args = parser.parse_args()

    print("config file is {}".format(args.config))
    parse_config(args.config)


if __name__ == "__main__":
    main()
