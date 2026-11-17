import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from pcc.gui import launch

    sys.exit(launch())
