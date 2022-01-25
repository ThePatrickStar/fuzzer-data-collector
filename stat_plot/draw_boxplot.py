###################
# draw boxplots based on plots generated by main.py
###################

import toml
import argparse
import os
import re
from pathlib import Path
import fnmatch
import pathlib
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from matplotlib.figure import figaspect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True, type=str)
    parser.add_argument("--verbose", "-v", required=False, action="store_true")
    parser.add_argument("--inputs", "-i", action='append', required=True)
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    verbose = args.verbose

    print("[*] config file is {}".format(config_path))

    conf_dict = {}
    with open(config_path) as config_file:
        conf_dict = toml.load(config_file)
        # TODO check config validity

    # draw a set of box plots for every folder
    for plot_dir in args.inputs:
        if not os.path.isdir(plot_dir):
            print(f"{plot_dir} is not a dir, skip")
            continue

        filenames = os.listdir(plot_dir)
        config_files = []

        for filename in filenames:
            for config_sig in conf_dict['config_sigs']:
                if re.search(config_sig, filename):
                    config_files.append(os.path.abspath(plot_dir + '/' + filename))

        # draw a set of boxplots for every target
        for config_file in config_files:
            if args.verbose:
                print(f"checking config file: {config_file}")
            plot_conf_dict = toml.load(open(config_file))
            # assume the out dir and the toml file are both in the root of args.in
            plot_out_path = os.path.abspath(plot_dir + '/' + pathlib.PurePath(plot_conf_dict['misc']['out_dir']).name)
            plot_aligned_dir = plot_out_path + '/aligned'
            plot_target = plot_conf_dict['misc']['project']
            plot_postfix = plot_conf_dict['misc']['file_postfix']

            fuzzers = os.listdir(plot_aligned_dir)

            # draw an individual boxplot for every data point
            for data_point in conf_dict['data_points']:
                out_dir_name = f'section-{data_point}-{plot_target}-{plot_postfix}'
                out_dir_path = os.path.abspath(plot_dir + '/' + out_dir_name)
                if not os.path.exists(out_dir_path):
                    os.makedirs(out_dir_path)

                # key: fuzzer val: [val]
                fuzzer_data = {}
                min_item_no = -1
                for fuzzer in fuzzers:
                    fuzzer_data[fuzzer] = []
                    fuzzer_data_dir = plot_aligned_dir + '/' + fuzzer
                    fuzzer_data_files = os.listdir(fuzzer_data_dir)
                    if min_item_no == -1 or len(fuzzer_data_files) < min_item_no:
                        min_item_no = len(fuzzer_data_files)
                    for fuzzer_data_file in fuzzer_data_files:
                        with open(fuzzer_data_dir + '/' + fuzzer_data_file) as data_file:
                            lines = data_file.readlines()
                            data_point = min(data_point, len(lines))
                            fuzzer_data[fuzzer].append(int(lines[data_point-1]))

                # trim the fuzzer_data so that all of them aligns for pandas DataFrame
                # TODO this may not be a desired default behavior, make this configurable
                for fuzzer in fuzzer_data:
                    fuzzer_data[fuzzer] = fuzzer_data[fuzzer][0:min_item_no]

                # data = np.array([fuzzer_data[fuzzer] for fuzzer in fuzzer_data]).T.tolist()
                try:
                    data = pd.DataFrame(data=fuzzer_data)
                    # TODO move duplicate code into functions; make more things configurable
                    w, h = figaspect(0.618)  # golden ratio
                    fig, ax = plt.subplots(figsize=(w, h))
                    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label]):
                        item.set_fontsize(16)
                    for item in (ax.get_xticklabels()):
                        item.set_fontsize(16)
                        # item.set_rotation(45)
                    for item in (ax.get_yticklabels()):
                        item.set_fontsize(16)
                    # for tick in ax.get_xticklabels():
                    #     tick.set_rotation(45)
                    # palette: "Greys", "ch:.25",
                    if conf_dict['y_start_0']:
                        ax.set_ylim(ymin=0)
                    box = sns.boxplot(ax=ax, data=data, orient="v", width=conf_dict['width'], palette=conf_dict['color_palette'], fliersize=0,
                                      dodge=False)
                    swarm = sns.swarmplot(ax=ax, orient="v", data=data, color=".25", size=8)

                    box.set_ylabel('# edges')

                    out_file_name_base = f'boxplot-{data_point}-{plot_target}-{plot_postfix}'

                    plt.savefig(out_dir_path+'/'+out_file_name_base+'.png')
                    plt.savefig(out_dir_path+'/'+out_file_name_base+'.pdf')
                    plt.clf()
                    plt.close(fig)

                    w, h = figaspect(0.618)  # golden ratio
                    fig, ax = plt.subplots(figsize=(w, h))
                    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label]):
                        item.set_fontsize(16)
                    for item in (ax.get_yticklabels()):
                        item.set_fontsize(16)
                    # for tick in ax.get_xticklabels():
                    #     tick.set_rotation(45)
                    if conf_dict['y_start_0']:
                        ax.set_ylim(ymin=0)
                    violin = sns.violinplot(ax=ax, data=data, orient="v", width=conf_dict['width'], palette=conf_dict['color_palette'], dodge=False,
                                            scale='width')
                    swarm = sns.swarmplot(ax=ax, orient="v", data=data, color=".25", size=8)

                    violin.set_ylabel('# edges')

                    out_file_name_base = f'violinplot-{data_point}-{plot_target}-{plot_postfix}'

                    plt.savefig(out_dir_path+'/'+out_file_name_base+'.png')
                    plt.savefig(out_dir_path+'/'+out_file_name_base+'.pdf')
                    plt.clf()

                    plt.close(fig)
                except Exception as e:
                    print(e)
                    print(f'skipping the plot for {out_dir_name}')


if __name__ == "__main__":
    main()
