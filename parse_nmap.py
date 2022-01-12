#!/usr/bin/env python3

import argparse

fingerprint_list = []
service_dict = {}

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("results")
    args = parser.parse_args()
    return args.results 

def strip_parens(ip):
    if "(" in ip:
        ip = ip.replace("(","")
    if ")" in ip:
        ip = ip.replace(")","")
    return ip

def grab_fingerprint(fileList):
    nice_scans = []
    meh_scans = []
    for block in fileList:
        if block.startswith("Nmap scan report for"): 
            if "Too many fingerprints" in block:
                firstLine = block.split("\n")[0]
                ip = firstLine.split(" ")[-1]
                ip = strip_parens(ip)
                fingerprint_list.append(ip)
            else: 
                nice_scans.append(block)
    return nice_scans

def grab_nice(nice_list):
    leftover_list = []
    for block in nice_list:
        if "Service Info" in block:
            serviceLine = block.split("\n")[-1]
            firstLine = block.split("\n")[0]
            ip = firstLine.split(" ")[-1]
            ip = strip_parens(ip)
            service_dict[ip] = serviceLine
        elif "Aggressive OS guesses" in block:
            split_lines = block.split("\n")
            firstLine = split_lines[0]
            ip = firstLine.split(" ")[-1]
            ip = strip_parens(ip)
            for line in split_lines:
                if "Aggressive OS guesses" in line:
                    service_dict[ip] = line
        elif ("general purpose" not in block and "Device type:" in block):
            split_lines = block.split("\n")
            firstLine = split_lines[0]
            ip = firstLine.split(" ")[-1]
            ip = strip_parens(ip)
            for line in split_lines:
                if "Device type:" in line:
                    device = line.split("Device type: ")[1]
                    service_dict[ip] = device
        elif "Running" in block:
            split_lines = block.split("\n")
            firstLine = split_lines[0]
            ip = firstLine.split(" ")[-1]
            ip = strip_parens(ip)
            for line in split_lines:
                if "Running" in line:
                    service = line.split("Running:")[1]
                    service_dict[ip] = service
        else:
            leftover_list.append(block)
    return leftover_list
            
def parse_file(result_file):
    with open(result_file) as f:
        myFile = f.read()
        fileList = myFile.split("\n\n")
    nice_list = grab_fingerprint(fileList)
    leftover_blocks = grab_nice(nice_list)
    return leftover_blocks

def write_to_file(leftover_blocks):
    fingerprint_file = open("fingerprints.txt", "w")
    for val in fingerprint_list:
        fingerprint_file.write(val + "\n")
    fingerprint_file.close()
    service_file = open("services.txt", "w")
    for val in service_dict:
        service_file.write(val + ":" + service_dict[val] + "\n")
    service_file.close()
    leftover_file = open("leftovers.txt", "w")
    for val in leftover_blocks:
        leftover_file.write(val + "\n\n")
    leftover_file.close()


def main():
    result_file = parse_args()
    leftover_blocks = parse_file(result_file)
    write_to_file(leftover_blocks)

main()
