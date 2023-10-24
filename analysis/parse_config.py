import os
import pprint
import subprocess
import sys


def parse_config(filename):
    d = {}
    c = open(filename, 'r')
    parsing_list = False
    for line in c:
        line=line.strip(' ')
        line=line.strip()
        if(line.startswith('#') or line == ''):
            continue
        elif parsing_list:
            if ')' in line:
                parsing_list=False
            else:
                line = line.strip('"')
                d[list_key].append(line)
        elif '=(' in line:
            list_key = line.split('=(')[0]
            d[list_key]=[]
            parsing_list = True
        else:
            try:
                l = line.split('=')
                k = l[0]
                v = l[1]
                v = v.strip('"')
                d[l[0]]=l[1]
            except:
                pass
    return d


def main():
    parse_config(sys.argv[1])


if __name__ == "__main__":
    main()
