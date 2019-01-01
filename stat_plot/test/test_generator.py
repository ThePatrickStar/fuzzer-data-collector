# run this script under the "test" folder
import random
import os


def main():
    fuzzer_list = ['cerebro', 'afl', 'aflfast']

    for (f, fuzzer) in enumerate(fuzzer_list):
        if not os.path.exists("data/"+fuzzer):
            os.makedirs("data/"+fuzzer)
        # generate 10 data files for each fuzzer
        for i in range(0, 10):
            file_name = "data/" + fuzzer + "/out-" + str(i) + ".txt"

            # randomly generate 900 - 1000 "seeds"
            seeds_no = random.randrange(900, 1001)

            # generate time slots (sec) for the seeds within 24 hours (86400s)
            slots = random.sample(range(0, 86400), seeds_no)

            if 0 not in slots:
                slots[0] = 0

            slots.sort()

            # generate the data no for the seeds
            data_nos = random.sample(range(5, 3000 - f * 100), seeds_no)

            if 5 not in data_nos:
                data_nos[0] = 5

            data_nos.sort()

            # write the slots and data_nos to file
            with open(file_name, 'w') as out_file:
                for (j, slot) in enumerate(slots):
                    out_file.write('{slot:{fill}{align}{width}}:{data}\n'.format(slot=slot, fill=' ', align=">"
                                                                                 , width=10, data=data_nos[j]))


if __name__ == "__main__":
    main()
