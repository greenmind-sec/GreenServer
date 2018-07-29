#!/usr/bin/python3

#title           :greenserver.py
#description     :Auxiliar no reconhecimento de alvos
#author          :JC GreenMind
#date            :28 Julho 2018
#version         :0.1
#usage           :sudo greenserver.py
#python version  :3
#
#=======================================================================
#
#



# LIBs MENU
import sys
import os
import time
import argparse

# LIBs Google Search
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote
from random import randint

# LIBs archive
import requests
import json
#import sys

# LIBs resolv
import socket
#import sys

# LIBs Traceroute
from scapy.all import *

# LIBs shodan
from shodan import Shodan
shodan_key = ""


# LIBs UrlParse
from urllib.parse import urlparse

# LIBs Check Robots.txt
#import requests

# LIBs WhatCMS
#import requests
chave_whatcms = ""


# LIBs Whois
#import requests

# LIBs Config
import json
#import os
json_file="config.json"

# LIBs green_img
from time import sleep
from sys import stdout, exit
from os import system, path


# LIBs green_load
from time import sleep
from sys import stdout, exit
inicio = 1
fim = 300



parser = argparse.ArgumentParser(description = 'GreenMind.')

parser.add_argument('--url','-u', action = 'store', dest = 'url',help = "usage -u 'http://businesscorp.com.br/'.")
parser.add_argument('-o','--output', action = 'store', dest = 'save', help = 'save output file.')
arguments = parser.parse_args()


msg_thc='''
                         .
                         C
                        GC;
       :               .CCC
        G              fCLC1
        ;CC           1CCLCC              1
        ,CLCG         LCCCCL           fC:
         LCCCCt       GCCCCC        :CLCi
          CCCCCC.     CCCCCC,     fCCCCL
           CCCCCC;    CCCCCC    GCCLCC;
           .CCCCCCf   iCCCCC  CCCCCCC
 .,          tCCCCCG  iCCCCG CCCCCCC
   ,CCCGC;    tCCLCCC .CCCCCtCCCCCf
     ,CLLCCCC1  LCCCC1 GCCC.CLCCL
       ,fCCCCCCCf;LCLC.CCC;CLCG    ,GCCCCCCLCCG.
          .GCCCCCCCC1GC CG1LG :GCCCCCGCCCCt,
    .............. Green Menu 0.1 ..............
'''
#--
#MSG Menu Principal
#--
msg_main_menu='''
%s
    1) Menu 01
    2) Menu 02
    3) Menu 03
  sair) Sair
'''%(msg_thc)
#
#=======================================================================
# definição Main - constantes
menu_actions  = {}


# LIBs
# Archive Search
def archive_search(url):
    archive = "http://archive.org/wayback/available"
    try:
        r = requests.post(archive, data={'url': url})
    except Exception as e:
        print("Ocorreu um erro: %s" % (e))
    return r.text

# =======================
# FUNÇÕES MENUS
# =======================
#--
# Função Menu principal
#--
def main_menu():
    os.system('clear')
    print(msg_main_menu)
    choice = input(" >>  ")
    exec_menu(choice)
    return
#--
# Função executa menu
#--
def exec_menu(choice):
    os.system('clear')
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print ("Invalid selection, please try again.\n")
            menu_actions['main_menu']()
    return
#
#--
# Função Voltar ao menu principal
#--
def back():
    menu_actions['main_menu']()
#--
# Função Sair programa
#--
def exit():
    os.system("clear")
    print("O %0 foi finalizado com segurança!")
    sys.exit()

def menu1():
    print("Menu 1")
    sys.exit()

def menu2():
    print("Menu 2")
    sys.exit()

def menu3():
    print("Menu 3")
    sys.exit()

#
#
#
#
#

def green_top(frase):
    RED, WHITE, CYAN, GREEN, END = '\033[91m', '\33[46m', '\033[36m', '\033[1;32m', '\033[0m'
    frase_img = '''{0}
        
┈┈┈┈╱▔▔▔▔▔▔╲┈╭━━━━━━━━━━━━━━━╮
┈┈┈▕┈╭━╮╭━╮┈▏┃%s 
┈┈┈▕┈┃╭╯╰╮┃┈▏╰┳━━━━━━━━━━━━━━╯
┈┈┈▕┈╰╯╭╮╰╯┈▏┈┃┈┈┈┈┈┈
┈┈┈▕┈┈┈┃┃┈┈┈▏━╯┈┈┈┈┈┈
┈┈┈▕┈┈┈╰╯┈┈┈▏┈┈┈┈┈┈┈┈
{1}{0}{1}
    '''.format(CYAN, END) %frase
    print(frase_img)

def green_traceroute(name_host):
    green_top("Traceroute init")
    # Realiza um traceroute com o maximo de 50 pulos
    pulos_traceroute = traceroute(name_host, maxttl=50)
    return pulos_traceroute

def green_urlparse(url):
    green_top("URL Parse init")
    data = urlparse(url)
    # Abre o dicionario
    dicionario_url = {}

    # Recebe HTTP ou HTTPS
    dicionario_url[0] = data.scheme

    # Recebe a URL
    dicionario_url[1] = data.netloc

    # Recebe o Path da aplicação
    dicionario_url[2] = data.path

    print("TIPO:" + dicionario_url[0])
    print("URL:" + dicionario_url[1])
    print("PATH:" + dicionario_url[2])
    return dicionario_url

def green_archive(url):
    green_top("Archive init")
    resposta_archive = json.loads(archive_search(url))
    return resposta_archive['results']

def green_gethostname(url):
    green_top("GetHostName init")
    name_host = socket.gethostbyname(url)
    return name_host

def green_traceroute(host_ip):
    green_top("Traceroute init")
    print(traceroute(host_ip,maxttl=50))

def green_checkrobots(url):
    green_top("Check Robots.txt init")
    try:
        resposta = requests.get(url + '/robots.txt')
        if (resposta.status_code == 200):
            print("[ Robots.txt ] - Encontrado")
            print(resposta.text)
        else:
            print("[ Robots.txt ] - Não encontrado")
    except Exception as e:
        print("Ocorreu um erro: %s" % (e))

def green_whatcms(site,chave_whatcms):
    green_top("WhatCMS init")
    # ADD Key WhatCMS
    api = "https://whatcms.org/APIEndpoint"

    r = requests.post(api, data={'key': chave_whatcms, 'url': site})
    if r.status_code == 0:
        status_resposta = "Server Failure"
    elif r.status_code == 100:
        status_resposta = "API Key Not Set"
    elif r.status_code == 101:
        status_resposta = "Invalid API Key"
    elif r.status_code == 110:
        status_resposta = "Url Parameter Not Set"
    elif r.status_code == 111:
        status_resposta = "Invalid Url"
    elif r.status_code == 120:
        status_resposta = "Too Many Requests"
    elif r.status_code == 121:
        status_resposta = "You have exceeded your monthly request quota"
    elif r.status_code == 123:
        status_resposta = "Account disabled per violation of Terms and Conditions"
    elif r.status_code == 200:
        status_resposta = "CMS Found"
        print(r.text)
        print(r.headers)
    elif r.status_code == 201:
        status_resposta = "CMS Not Found"
    elif r.status_code == 202:
        status_resposta = "Requested Url Was Unavailable"
    else:
        status_resposta = "Algo errado!"

def green_whois(name_host):
    green_top("Whois init")
    url_api = "http://api.hackertarget.com/whois/?q="
    requisicao = requests.get(url_api + name_host)
    print(requisicao.text)

def green_shodansearch(name_host,shodan_key):
    # Lookup an IP
    green_top("Shodan init")
    # ADD Key config
    api = Shodan(shodan_key)
    host = api.host(name_host)
    # print(ipinfo)
    # Print general info
    print("""
IP: {}
Organization: {}
Operating System: {}
                    """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
    # Print all banners
    for item in host['data']:
        print("""
Port: {}                  
                            """.format(item['port']))

def green_load(inicio,fim):
    RED, WHITE, CYAN, GREEN, END = '\033[91m', '\33[46m', '\033[36m', '\033[1;32m', '\033[0m'
    for i in range(101):
        sleep(0.01)
        stdout.write("\r{0}[{1}*{0}]{1} Preparing environment... %d%%".format(CYAN, END) % i)
        stdout.flush()

# LIBs
# Google Search
def green_googlesearch(url):
    green_top("Google init")
    termo_digitado = "site:" + url
    for inicia_resultados_em in [0, 10, 20, 30, 50]:
        parametros_de_busca = {'q': termo_digitado, 'start': inicia_resultados_em}

        pagina_de_busca = requests.get('https://www.google.com.br/search',
                                       params=parametros_de_busca)

        soup = BeautifulSoup(pagina_de_busca.text, "html.parser")

        for item in soup.find_all('h3', attrs={'class': 'r'}):
            if item.a:
                link_sujo_do_google = item.a.attrs['href']
                # /url?website.com%3Fid%3D100%26x%3Dy&ui=10....

                link_sem_url_inicial = link_sujo_do_google[7:]
                # website.com%3Fid%3D100%26x%3Dy&ui=10....

                link_os_parametros_do_google = link_sem_url_inicial.split('&')[0]
                # website.com%3Fid%3D100%26x%3Dy

                link_final_decodificado = unquote(link_os_parametros_do_google)
                # website.com?id=100&x=y

                print(link_final_decodificado)
        dorme_por = randint(0, 2)
        time.sleep(dorme_por)

# =======================
# DEFINIÇÃO DE MENUS
# =======================
menu_actions = {
    #--
    # Menu principal
    #--
    'main_menu': main_menu,
    '1': menu1,
    '2': menu2,
    '3': menu3,
    #--
    # Voltar e Sair
    #--
    'voltar': back,
    'sair': exit,
}

# Check Root
# =======================
if os.geteuid() != 0:
    print("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    sys.exit()
else:
    # Check config
    if os.path.exists(json_file) != True:
        print("Config not found!")
        sys.exit()
    else:
        json_data = open(json_file)
        data = json.load(json_data)
        json_data.close()
        if data["key"] != "greenmind":
            print("Error Key")
            sys.exit()
        else:
            print ("Key OK!")
            if arguments.url == None or arguments.save == None:
                main_menu()
            else:

                # ===============================================
                # GOOGLE SEARCH
                green_googlesearch(arguments.url)
                #green_load(inicio, fim)

                # ===============================================
                # ARCHIVE SEARCH
                retorno_archive = green_archive(arguments.url)
                print(retorno_archive)
                #green_load(inicio, fim)

                # URLParse
                # ===============================================
                retorno_urlparse = green_urlparse(arguments.url)
                #green_load(inicio, fim)


                # ===============================================
                # GETHOSTNAME
                retorno_gethostname = green_gethostname(retorno_urlparse[1])
                print(retorno_gethostname)
                #green_load(inicio, fim)
                

                # ===============================================
                # TRACEROUTE
                green_traceroute(retorno_gethostname)
                #green_load(inicio, fim)

                # WHOIS
                # ===============================================
                green_whois(retorno_gethostname)
                #green_load(inicio, fim)

                # SHODAN SEARCH
                # ===============================================
                green_shodansearch(retorno_gethostname,shodan_key)
                #green_load(inicio, fim)

                # Check Robots.txt
                # ===============================================
                green_checkrobots(arguments.url)
                #green_load(inicio, fim)

                # Whatcms
                # ===============================================
                green_whatcms(arguments.url,chave_whatcms)
                #green_load(inicio, fim)



                '''
                # SHARINGMYIP

                # TheHarvester

                # Netcraft

                # Censys

                # DNSdumpster

                # Bing busca avançada

                # Arin

                # Datasploit
                '''




