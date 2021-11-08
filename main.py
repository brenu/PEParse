import argparse
import os
import sys
import lief

def callWithoutPrinting(function, *args, **kwargs):
    originalStdout = sys.stdout
    param = kwargs.get('param', None)
    result = None

    with open(os.devnull, "w") as devnull:
        try:
            sys.stdout = devnull
            if param:
                result = function(param)
            else:
                result = function()
        finally:
            sys.stdout = originalStdout
            return result


def main():
    argumentParser = argparse.ArgumentParser()
    argumentParser.add_argument('File', metavar='file',
                                type=str,
                                help='Path to the PE file. Ex: peparse.py ./happy.exe')

    arguments = argumentParser.parse_args()

    inputFile = arguments.File

    if not os.path.isfile(inputFile):
        print('No file found.\n')
        sys.exit(-1)

    try:
        executablePath = inputFile
        binary = callWithoutPrinting(lief.parse, param=executablePath)

        print("\n-> Looking up for function symbols <-\n")
        if binary.symbols:
            print("\nFUNCTION SYMBOLS")
            for item in binary.symbols:
                if item.complex_type == lief.PE.SYMBOL_COMPLEX_TYPES.FUNCTION and not "mingw" in item.name:
                    print("[*] {}".format(item.name))
        else:
            print("-> No symbols found, trying alternative methods... <-\n\n")

            if callWithoutPrinting(lambda: binary.imports):
                print("FUNCTION IMPORTS")
                for singleImport in binary.imports:
                    print("{}".format(singleImport.name))
                    for function in singleImport.entries:
                        print("    [*] {}".format(function.name))

            if callWithoutPrinting(lambda: binary.exported_functions):
                print("\n\n\nFUNCTION EXPORTS")
                for singleExport in binary.exported_functions:
                    print("    [*] {}".format(singleExport.name))

            if callWithoutPrinting(lambda: binary.exception_functions):
                print("\n\n\nEXCEPTION FUNCTIONS")
                for singleException in binary.exception_functions:
                    print("    [*] {}".format(singleException.name))

        print("\n-> Lookup process completed :) <-\n")
    except:
        print("\n[*] An unknown behaviour lead us to an exception\n")
        sys.exit(-1)


main()
