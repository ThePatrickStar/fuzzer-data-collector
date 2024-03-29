# fuzzer-data-collector
Overall workflow:
1. use the `showmaps` program to generate the raw data
2. use the python scripts under `stats_plot` to draw the plots & generate statistic analysis results

## showmaps

```bash
# build (under the showmaps folder)
make

# generate the raw data in the format ("time slot":"edge/path number")
# the usage of showmaps is very similar to afl-showmap
# -q means quite mode, will "eat" the output of the original program
# -s means skipping individual seed trace generation (will not generate a trace file for each seed)
# -S means skipping the first 'n' files (useful when we only want to calculate the increment in code coverage)
# everything after "--" is the same as how you run AFL
./showmaps -i $PATH_TO_QUEUE_FOLDER -o data/queue -q -s -S 0 -- $AFL_INSTRUMENTED_PROGRAM @@ 
```

## stat_plot

```bash
# install the environment
virtualenv -p python3 venv

source venv/bin/activate

pip install -r requirements.txt

# run the script under the virtual environment
# before running the script, you need to prepare the .toml config file
python main.py -c $PATH_TO_TOML_CONFIG
```

## Toml Config
Example configs are available under the `stat_plot/test` folder.

The example for plotting the line chart is the `test_config.toml` file.

The `data_files` option should point to the files generated by `showmaps`.


