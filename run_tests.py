import os
import argparse
import unittest
import inspect
from tests.payload_interface import test_payload


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run specific test method.')
    parser.add_argument('--method', dest='method_name', action='store',
                        help='Specify a test method to run')

    args, remaining_argv = parser.parse_known_args()

    if args.method_name:
        test_classes = [cls for name, cls in inspect.getmembers(test_payload)
                        if inspect.isclass(cls) and issubclass(cls, unittest.TestCase)]
        suite = unittest.TestSuite()
        for class_ in test_classes:
            if hasattr(class_, args.method_name):
                suite.addTest(class_(args.method_name))
        unittest.TextTestRunner().run(suite)
    else:
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir=os.path.dirname(test_payload.__file__))
        runner = unittest.TextTestRunner()
        runner.run(suite)
