import argparse

def main():
    parser = argparse.ArgumentParser(description="A simple CLI tool using argparse.")
    
    # Optional argument
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    
    # Required argument
    parser.add_argument('input_file', type=str, help='Input file to process')
    
    args = parser.parse_args()
    
    if args.verbose:
        print("Verbose mode is enabled.")
    
    print(f"Processing input file: {args.input_file}")

if __name__ == "__main__":
    main()
