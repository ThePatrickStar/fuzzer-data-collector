import toml


def parse_config(config_path):
    print("haha")
    with open(config_path) as config_file:
        conf_dict = toml.load(config_file)
        print(conf_dict)
