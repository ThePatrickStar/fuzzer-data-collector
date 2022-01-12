import toml
import argparse
import os
import re
from pathlib import Path
import fnmatch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True, type=str)
    parser.add_argument("--verbose", "-v", required=False, action="store_true")
    parser.add_argument("--output", "-o", required=True, type=str)
    parser.add_argument("--inputs", "-i", action='append', required=True)
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    verbose = args.verbose

    #print('inputs is %s' % (args.inputs))
    #print('output is %s' % (args.output))
    #exit(1)
    print("[*] config file is {}".format(config_path))

    conf_dict = {}
    with open(config_path) as config_file:
        conf_dict = toml.load(config_file)
        # TODO check config validity

    if not os.path.exists(args.output):
        os.makedirs(args.output)

    # find all the data files
    all_data_files = []
    for fname in conf_dict['objective_filenames']:
        for base_dir in args.inputs:
            for fpath in Path(base_dir).rglob(fname):
                if verbose:
                    print(os.path.abspath(str(fpath)))
                all_data_files.append(fpath)

    # create one config for every target * obj
    for t, target_name in enumerate(conf_dict['target_names']):
        for o, objective in enumerate(conf_dict['objectives']):

            misc_dict = {
                "bucket": conf_dict["bucket"],
                "confidence_lvl": conf_dict["confidence_lvl"],
                "out_dir": args.output + "/" + "plot-"+target_name+"-"+objective+"-out/",
                "ylabel": conf_dict["objective_y_labels"][o],
                "file_postfix": conf_dict["file_postfixes"][o],
                "project": conf_dict["target_names"][t],
                "max_time": conf_dict["max_time"],
                "stat_type": conf_dict["stat_type"],
                "large_font": conf_dict["large_font"],
                "no_legend": conf_dict["no_legend"],
                "y_start_0": conf_dict["y_start_0"],
                "x_log_scale": conf_dict["x_log_scale"],
                "y_log_scale": conf_dict["y_log_scale"]
            }

            fuzzer_dict = {}
            for f, fuzzer_name in enumerate(conf_dict["fuzzer_names"]):
                data_files = [os.path.abspath(str(data_file)) for data_file in all_data_files
                              if re.search(conf_dict['fuzzer_sigs'][f], str(data_file)) and
                              re.search(conf_dict['target_sigs'][t], str(data_file)) and
                              fnmatch.fnmatch(data_file.name, conf_dict['objective_filenames'][o])]
                if len(data_files) > 0:
                    fuzzer_dict[fuzzer_name] = {
                        "data_files": sorted(data_files),
                        "line_style": conf_dict['fuzzer_line_styles'][f],
                        "line_color": conf_dict['fuzzer_line_colors'][f]
                    }

            out_dict = {
                "fuzzers": fuzzer_dict,
                "misc": misc_dict
            }

            plot_config_name = "plot-"+target_name+"-"+objective+".toml"
            plot_config_path = args.output + "/" + plot_config_name

            with open(plot_config_path, 'w') as handle:
                toml.dump(out_dict, handle)


if __name__ == "__main__":
    main()
