import os
import sys
import argparse
import logging

from katnip.targets.application import ApplicationTarget
from katnip.controllers.server.windbgcontroller import WinAppDbgController
from kitty.fuzzers.server import ServerFuzzer
from kitty.interfaces.web import WebInterface
from kitty.model import GraphModel
from kitty.model import Static
from kitty.model import Template


# logging levels dict
levels = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL
}


class NmFuzzer(object):

    @staticmethod
    def parse_args():
        """ CLI args parser
        """
        parser = argparse.ArgumentParser(
            prog="NmFuzz",
            description="NetworkMiner PCAP parsing fuzzer",
            epilog="Returns 0 if successful, -1 otherwise"
        )

        mand = parser.add_argument_group("mandatory")
        mand.add_argument("-p", "--program", dest="target_prog", required=True, type=str)

        # Optional arguments
        opt = parser.add_argument_group("Optional")
        opt.add_argument("-l", "--log_level", dest="log_level", default="error", type=str,
                         choices=[choice for choice in levels.keys()])

        return parser.parse_args()

    @staticmethod
    def logger(level, name, logfile):
        """ Create and configure file and console logging.
        :param level: console debugging level only
        :param name: logger name
        :param logfile: log filename
        :return: configured logging object
        """
        logger = logging.getLogger(name)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        file_handler = logging.FileHandler(logfile)
        file_handler.setLevel(logging.DEBUG)
        console_formatter = logging.Formatter("[%(levelname)s] %(message)s")
        file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(console_formatter)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    @classmethod
    def main(cls):
        """ Main NmFuzzer function
        :return: 0 if successful, -1 otherwise
        """
        args = cls.parse_args()
        logger = cls.logger(levels[args.log_level], "NetworkMiner.fuzz", "./session.log")
        prog = os.path.abspath(args.target_prog)

        # define target
        target = ApplicationTarget(
            "NetworkMiner",
            path=prog,
            args="",
            timeout=5,
            logger=logger
        )

        # define the Controller
        controller = WinAppDbgController(
            "WinDBG",
            process_path=prog,
            process_args=[],
            logger=logger
        )

        target.set_controller(controller)

        # Template
        t1 = Template(name="T1", fields=[
            Static("\xd4\xc3\xb2\xa1", name="S1_1"),
        ])

        model = GraphModel()
        model.connect(t1)

        # define the fuzzing session
        fuzzer = ServerFuzzer(
            name="NetworkMiner fuzzer",
            logger=logger,
        )
        fuzzer.set_interface(WebInterface())
        fuzzer.set_model(model)
        fuzzer.set_target(target)

        # Start
        try:
            fuzzer.start()
            logger.info("Done with fuzzing")
            raw_input("Press enter to exit...")
            fuzzer.stop()

        except KeyboardInterrupt:
            logger.info("Session interrupted by user...")
            fuzzer.stop()
            return 1

        except Exception as exc:
            logger.error(exc)
            fuzzer.stop()
            return -1

        return 0


if __name__ == '__main__':
    sys.exit(NmFuzzer.main())
