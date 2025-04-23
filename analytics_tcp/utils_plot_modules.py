import matplotlib.pyplot as plt
import numpy as np


def produce_pdf(data: list[tuple[list, str]], savename: str="output.png",
                x_unit: str| None = None, title: str | None = None,
                logscale: bool = False,
                density: bool = True) -> None:
    
    for ins, lab in data:
        plt.hist(ins, density=density, alpha=0.5, label=lab)

    plt.ylabel("Density")
    if logscale:
        plt.xscale("log")
    if x_unit:
        plt.xlabel(x_unit)
    if title:
        plt.title(title)

    plt.legend()
    plt.grid(True)
    plt.savefig(savename)
    plt.close()


def produce_cdf(data: list[tuple[list, str]], savename: str="output.png",
                x_unit: str| None = None, title: str | None = None,
                logscale: bool = False) -> None:
    
    for ins, lab in data:
        sorted_ins = np.sort(ins)
        cdf = np.arange(1, len(sorted_ins) + 1) / len(sorted_ins)
        plt.plot(sorted_ins, cdf, marker='.', linestyle='-', label=lab)
    plt.ylabel("Probability")
    if logscale:
        plt.xscale("log")
    if x_unit:
        plt.xlabel(x_unit)
    if title:
        plt.title(title)

    plt.legend()
    plt.grid(True)
    plt.savefig(savename)
    plt.close()