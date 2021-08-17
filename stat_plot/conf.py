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
            fuzzer['name'] = fuzzer_name
            if 'line_style' not in fuzzer:
                fuzzer['line_style'] = 'solid'
            # only for boxplot stat_type
            if 'box_color' not in fuzzer:
                fuzzer['box_color'] = 'white'
            if len(fuzzer["data_files"]) == 0:
                print("[!] {} has no data file!".format(fuzzer_name))
                config_valid = False

        if 'stat_type' not in misc_dict:
            print("[!] [misc] table misses 'stat_type'!")
            config_valid = False

        valid_stat_types = ['overall', 'stest', 'boxplot', 'scatterplot', 'histogram']
        if misc_dict['stat_type'] not in valid_stat_types:
            print("[!] invalid stat_type: {}".format(misc_dict['stat_type']))
            config_valid = False

        if misc_dict['stat_type'] == 'overall':

            if "bucket" not in misc_dict:
                misc_dict["bucket"] = ["s"]
            else:
                bucket_valid, bucket = check_bucket(misc_dict["bucket"])
                if not bucket_valid:
                    config_valid = False
                misc_dict["bucket"] = bucket

            if "confidence_lvl" not in misc_dict:
                misc_dict["confidence_lvl"] = 0.95

            required_keys = ["out_dir", "ylabel", "file_postfix", "project", "max_time"]

            for r_key in required_keys:
                if r_key not in misc_dict:
                    print("[!] {} (required) is missing is [misc]!".format(r_key))
                    config_valid = False

            if 'x_log_scale' not in misc_dict:
                misc_dict['x_log_scale'] = False
            if 'y_log_scale' not in misc_dict:
                misc_dict['y_log_scale'] = False

        elif misc_dict['stat_type'] == 'stest':

            required_keys = ["out_dir", "project", "file_postfix"]

            for r_key in required_keys:
                if r_key not in misc_dict:
                    print("[!] {} (required) is missing is [misc]!".format(r_key))
                    config_valid = False

        elif misc_dict['stat_type'] == 'boxplot':

            required_keys = ["out_dir", "project", "file_postfix", "notch", 'plot_title']

            for r_key in required_keys:
                if r_key not in misc_dict:
                    print("[!] {} (required) is missing is [misc]!".format(r_key))
                    config_valid = False

            if 'ylim' in misc_dict:
                # TODO: add type check
                if len(misc_dict['ylim']) != 2:
                    print('[!] invalid ylim: {} in [misc]!'.format(misc_dict['ylim']))

        elif misc_dict['stat_type'] == 'scatterplot':

            required_keys = ["out_dir", "project", "file_postfix", 'plot_title', 'xlabel', 'ylabel', 'large_font']

            for r_key in required_keys:
                if r_key not in misc_dict:
                    print("[!] {} (required) is missing is [misc]!".format(r_key))
                    config_valid = False

        elif misc_dict['stat_type'] == 'histogram':

            required_keys = ["out_dir", "project", "file_postfix", 'plot_title', 'xlabel', 'ylabel',
                             'large_font', 'n_bins']

            for r_key in required_keys:
                if r_key not in misc_dict:
                    print("[!] {} (required) is missing is [misc]!".format(r_key))
                    config_valid = False

        return config_valid, fuzzers_dict, misc_dict
