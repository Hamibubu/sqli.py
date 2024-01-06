# SQLi.py - Automated Time-Based Blind SQL Injection Tool

## Overview

**SQLi.py** is a Python script designed for automating Time-Based Blind SQL Injection attacks. The script requires the `-u` parameter with the URL and the GET parameter.

## Prerequisites

- Python 3
- `pwn` library
- Other required libraries (install them using `pip install -r requirements.txt`)

## Usage

```bash
python sqli.py -u <target_url>
```
-u, --url: The target URL with the vulnerable parameter, and the get param(now just working with 1)

## Features

Automated Time-Based Blind SQL Injection attacks.
Utilizes pwn library for visuals.

## Installation

Clone the repository:

```bash
git clone https://github.com/hamibubu/sqli.py.git
cd sqli.py
```
Install the required dependencies:

```bash
pip install -r requirements.txt
```

Run the script with the appropriate parameters:

```bash
python sqli.py -u <target_url>
```
## Example

```bash
python sqli.py -u http://example.com/vulnerable_page.php?id=12
```