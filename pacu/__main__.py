import sys
import pacu


def main(args=None):
    """The main routine."""
    if args is None:
        args = sys.argv[1:]

    pacu.Main().run()


if __name__ == "__main__":
    sys.exit(main())
