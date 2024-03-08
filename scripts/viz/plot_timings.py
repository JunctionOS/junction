#!/usr/bin/env python3

import click
import io
import matplotlib.pyplot as plt
import pandas
import sys
import logging


def load_table_from_file(file):
    if file.endswith(".dat") or file.endswith(".csv"):
        return pandas.read_table(
            file, header=None, names=[
                'time', 'trace'], delim_whitespace=True)
    else:
        raise ValueError(
            'file must be a dat/csv file. found {}'.format(file))


def load_table_from_stdin():
    try:
        return pandas.read_table(
            sys.stdin, header=None, names=[
                'time', 'trace'], delim_whitespace=True)
    except BaseException as e:
        logging.exception('')
        raise ValueError('could not load stdin as dat/csv, aborting')


def transpose_dataframe(df):
    renaming_dict = {(idx): label for (idx, label) in enumerate(df['trace'])}
    df = df.drop('trace', axis=1)
    df.rename(renaming_dict, inplace=True)

    return df.transpose()


def plot_dataframe(df, output_filename, scale):
    df.plot(kind='barh',
            stacked=True,
            title='Timing breakdown',
            xlabel='time ({})'.format(scale)).legend(loc='upper center',
                                                     bbox_to_anchor=(.5,
                                                                     2))

    plt.savefig(output_filename,
                dpi=100,
                bbox_inches='tight'
                )


@click.command("plot",
               help="plot a bar chart with the timings obtained from timings.awk")
@click.argument("file", type=click.Path(exists=True), required=False)
@click.option("--output", "-o", type=click.Path(), required=False)
@click.option("--scale", "-s", type=click.STRING, default="s")
def plot(file, output, scale):
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

    print(df)
    df = transpose_dataframe(df)
    plot_dataframe(df, output, scale)


if __name__ == '__main__':
    logging.basicConfig()
    plot()
