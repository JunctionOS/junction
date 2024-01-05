#!/usr/bin/env python

import click
import io
import json
import matplotlib.pyplot as plt
import pandas
import sys
import logging


def load_table_from_file(file):
    if file.endswith(".dat") or file.endswith(".csv"):
        return pandas.read_table(
            file, header=None, names=[
                'time', 'trace'], delim_whitespace=True)
    elif file.endswith(".json"):
        with open(file, 'r') as fp:
            json_obj = json.load(fp)
            json_list = sorted(
                [(float(k), v) for k, v in json_obj.items()], key=lambda x: float(x[0]))

        return pandas.DataFrame(json_list, columns=['time', 'trace'])
    else:
        raise ValueError(
            'file must be a dat, csv or json file. found {}'.format(file))


def load_table_from_stdin():
    stdin = sys.stdin.read()
    json_exception = None
    try:
        json_obj = json.loads(stdin)
        json_list = sorted(
            [(float(k), v) for k, v in json_obj.items()], key=lambda x: float(x[0]))

        if not json_list:
            raise ValueError('empty json')

        return pandas.DataFrame(json_list, columns=['time', 'trace'])
    except BaseException as e:
        json_exception = e
        pass

    try:
        fp = io.StringIO(stdin)
        return pandas.read_table(
            fp, header=None, names=[
                'time', 'trace'], delim_whitespace=True)
    except BaseException as e:
        try:
            if json_exception:
                raise json_exception
        except BaseException:
            logging.exception('')

        logging.exception('')
        raise ValueError('could not load stdin as csv, dat or json, aborting')


def compute_partials(df):
    # add dummy event START
    df.loc[-1] = [0, 'START']
    df.index = df.index + 1
    df = df.sort_index()

    # compute partial diffs
    df['time'] = df['time'].diff()

    # drop dummy event
    df = df.drop(0)

    return df


def transpose_dataframe(df):
    renaming_dict = {(idx + 1): label for (idx, label)
                     in enumerate(df['trace'])}
    df = df.drop('trace', axis=1)
    df.rename(renaming_dict, inplace=True)

    return df.transpose()


def plot_dataframe(df, output_filename):
    df.plot(
        kind='barh',
        stacked=True,
        title='Timing breakdown',
        xlabel='time (s)').legend(loc='upper center', bbox_to_anchor=(.5, 2))

    plt.savefig(output_filename,
                dpi=100,
                bbox_inches='tight'
                )


@click.command("plot",
               help="plot a bar chart with the timings obtained from timings.awk")
@click.argument("file", type=click.Path(exists=True), required=False)
@click.option("--output", "-o", type=click.Path(), required=False)
def plot(file, output):
    try:
        if file:
            df = load_table_from_file(file)
            if not output:
                output = '{}.svg'.format('.'.join(file.split('.')[:-1]))
        else:
            df = load_table_from_stdin()
            if not output:
                output = 'output.svg'
    except BaseException:
        logging.exception('failed to load dataframe')
        return

    df = compute_partials(df)
    df = transpose_dataframe(df)
    plot_dataframe(df, output)


if __name__ == '__main__':
    logging.basicConfig()
    plot()
