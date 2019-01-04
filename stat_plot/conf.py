import toml


def check_bucket(bucket):
    valid_buckets = ["sec", "s", "min", "m", "hour", "h"]
    bucket = bucket.lower()

    if bucket not in valid_buckets:
        print("[!] invalid bucket value: {}".format(bucket))
        return False, bucket
    else:
        bucket = bucket[0]
        return True, bucket


def parse_config(config_path):
    config_valid = True

    with open(config_path) as config_file:
        conf_dict = toml.load(config_file)

        fuzzers_dict = conf_dict['fuzzers']

        misc_dict = conf_dict['misc']

        # sanitize the config
        for fuzzer_name in fuzzers_dict:
            fuzzer = fuzzers_dict[fuzzer_name]
            if len(fuzzer["data_files"]) == 0:
                print("[!] {} has no data file!".format(fuzzer_name))
                config_valid = False

        if "bucket" not in misc_dict:
            misc_dict["bucket"] = ["s"]
        else:
            bucket_valid, bucket = check_bucket(misc_dict["bucket"])
            if not bucket_valid:
                config_valid = False

        if "confidence_lvl" not in misc_dict:
            misc_dict["confidence_lvl"] = 0.95

        required_keys = ["out_dir", "ylabel", "file_postfix", "project", "max_time"]

        for r_key in required_keys:
            if r_key not in misc_dict:
                print("[!] {} (required) is missing is [misc]!".format(r_key))
                config_valid = False

        return config_valid, fuzzers_dict, misc_dict
