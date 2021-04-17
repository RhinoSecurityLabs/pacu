import sys
import pacu.main


def main(args=None):
    """The main routine."""
    if args is None:
        args = sys.argv[1:]

    pacu.main.Main().run()


if __name__ == "__main__":
    sys.exit(main())
