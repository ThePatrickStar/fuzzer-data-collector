import matplotlib.pyplot as plt
import numpy as np
import scipy.stats
import os


def mean_confidence_interval(data, confidence):
    a = 1.0 * np.array(data)
    n = len(a)
    m, se = np.mean(a), scipy.stats.sem(a)
    h = se * scipy.stats.t.ppf((1+confidence)/2., n-1)
    return m, m-h, m+h


def row_to_col(rows):
    return [*zip(*rows)]


def mkdirs(path):
    if not os.path.exists(path):
        os.makedirs(path)


# align data files
def align_data(fuzzer_dict, misc_dict):

    fuzzer_name = fuzzer_dict['name']
    data_files = fuzzer_dict['data_files']
    out_dir = misc_dict['out_dir']
    aligned_dir = out_dir + "/aligned/" + fuzzer_name + '/'
    max_slot = int(misc_dict['max_time']) * 3600

    mkdirs(aligned_dir)

    new_data_files = []
    for (j, data_file) in enumerate(data_files):
        slots = []
        vals = []
        with open(data_file) as df:
            lines = df.readlines()

            for line in lines:
                tokens = line.split(":")
                slot = int(tokens[0])
                val = int(tokens[1])
                if slot > max_slot:
                    break
                slots.append(slot)
                vals.append(val)

        slot_idx = 0
        new_vals = []

        for i in range(0, max_slot):
            if i > slots[slot_idx]:
                slot_idx = min(len(slots)-1, slot_idx + 1)
            new_vals.append(vals[slot_idx])

        new_data_file = aligned_dir + str(j) + ".txt"
        with open(new_data_file, "w") as out_file:
            for val in new_vals:
                out_file.write(str(val)+'\n')

        new_data_files.append(new_data_file)

    fuzzer_dict['data_files'] = new_data_files


# add plots to ax; write the computed data out
# TODO: use bucket
def plot_files(fuzzer_dict, misc_dict, ax):
    entire_data_row = []

    align_data(fuzzer_dict, misc_dict)

    data_files = fuzzer_dict['data_files']

    for data_file in data_files:
        data_row = []
        with open(data_file) as df:
            lines = df.readlines()
            for line in lines:
                data_row.append(int(line))
        entire_data_row.append(data_row)

    entire_data_col = row_to_col(entire_data_row)

    means = []
    mins = []
    maxs = []
    bins = []

    for col in entire_data_col:
        mean, min_, max_ = mean_confidence_interval(col, misc_dict['confidence_lvl'])
        means.append(mean)
        mins.append(max(min_, 0))
        maxs.append(max_)

    data_dir = misc_dict['out_dir'] + '/' + 'stat_data/'
    mkdirs(data_dir)

    fuzzer_name = fuzzer_dict['name']

    with open(data_dir + fuzzer_name + "-mean-confi.txt", "w") as df:
        for (idx, mean) in enumerate(means):
            df.write("{},{},{}\n".format(mean, mins[idx], maxs[idx]))
            bins.append(idx)

    set_line_color = 'line_color' in fuzzer_dict
    set_line_style = 'line_style' in fuzzer_dict

    if set_line_color and set_line_style:
        ax.plot(bins[0:], means[0:], label=fuzzer_name, linestyle=fuzzer_dict['line_style'], color=fuzzer_dict['line_color'])
        ax.fill_between(bins[0:], mins[0:], maxs[0:], facecolor=fuzzer_dict['line_color'], alpha=0.2)
    elif set_line_color:
        ax.plot(bins[0:], means[0:], label=fuzzer_name, color=fuzzer_dict['line_color'])
        ax.fill_between(bins[0:], mins[0:], maxs[0:], facecolor=fuzzer_dict['line_color'], alpha=0.2)
    elif set_line_style:
        ax.plot(bins[0:], means[0:], label=fuzzer_name, linestyle=fuzzer_dict['line_style'])
        ax.fill_between(bins[0:], mins[0:], maxs[0:], alpha=0.2)
    else:
        ax.plot(bins[0:], means[0:], label=fuzzer_name)
        ax.fill_between(bins[0:], mins[0:], maxs[0:], alpha=0.2)


def generate_plots(fuzzers_dict, misc_dict):
    fig = plt.figure(1)
    ax = fig.add_subplot(111)

    for fuzzer_name in fuzzers_dict:
        print('[*] generating plots for {}'.format(fuzzer_name))
        fuzzer_dict = fuzzers_dict[fuzzer_name]
        plot_files(fuzzer_dict, misc_dict, ax)

    out_dir = misc_dict['out_dir'] + '/'
    base_filename = out_dir + misc_dict["project"] + "_overall" + misc_dict["file_postfix"]
    filename_pdf = base_filename + '.pdf'
    filename_png = base_filename + '.png'

    ax.set(xlabel='time (sec)', ylabel=misc_dict['ylabel'])
    ax.legend()
    fig.savefig(filename_pdf)
    fig.savefig(filename_png)
