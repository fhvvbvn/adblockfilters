import os
import sys
import re
from typing import Tuple,Dict,Set

from tld import get_tld
import IPy
from loguru import logger

from readme import Rule

class Resolver(object):
    def __init__(self, path:str):
        self.path = path

    def __analysis(self, address:str) -> Tuple[str]:
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            return res.fld, res.subdomain
        except Exception as e: 
            ip = address
            if ip.rfind(":") > 0:
                ip = ip[:ip.rfind(":")]
            try:
                ip_address = IPy.IP(ip)
                if ip_address.iptype() != "PUBLIC":
                    raise Exception('"%s": not public ip'%(address))
                return address, ""
            except Exception as e: 
                raise Exception('"%s": not domain or ip'%(address))

    # host 模式
    def __resolveHost(self, line) -> Tuple[str]:
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block=None
            while True:
                # #* 注释
                if match('^#.*', line):
                    break
                if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                    row = line.split(' ')
                    for i in range(len(row)-1, -1, -1):
                        if len(row[i]) == 0:
                            row.pop(i)
                    domain = row[1]
                    if domain not in ['localhost', 'localhost.localdomain', 'local', '0.0.0.0']:
                        block = self.__analysis(domain)
                        break
                raise Exception('"%s": not keep'%(line))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block
        
    # dns 模式
    def __resolveDNS(self, line) -> Tuple[Tuple[str],Tuple[str],str]:
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block,unblock,filter=None,None,None
            while True:
                # !* 注释
                if match('^!.*', line):
                    break
                # [*] 注释
                if match('^\[.*\]$', line):
                    break
                # #* 注释
                if match('^#.*', line):
                    break

                if line.find(' ') > 0:
                    line = line[:line.find(' ')]

                # ||example.org^: block access to the example.org domain and all its subdomains, like www.example.org.
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('/') >= 0:
                        filter = line
                        break
                    if domain.find('*') >= 0:
                        if domain.startswith('*.') and domain[2:].find('*')<0:
                            domain = domain[2:]
                            block = self.__analysis(domain)
                            break
                        else:
                            filter = line
                            break
                    block = self.__analysis(domain)
                    break
                # @@||example.org^: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__analysis(domain)
                    break
                # /REGEX/: block access to the domains matching the specified regular expression
                if match('^/.*/$', line):
                    filter = line
                    break
                if line.find('$') > 0 or match('^\|\|.*', line):
                    filter = line
                    break
                # other
                raise Exception('"%s": not keep'%(line))
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block,unblock,filter
        
    # filter 模式
    def __resolveFilter(self, line) -> Tuple[Tuple[str],Tuple[str],str]:
        def match(pattern, string):
            return True if re.match(pattern, string) else False
        try:
            block,unblock,filter=None,None,None
            while True:
                # !* 注释
                if match('^!.*', line):
                    break
                # [*] 注释
                if match('^\[.*\]$', line):
                    break
                # #* 注释
                if match('^#.*', line):
                    break

                if match('^.*third-party.*', line):
                    break

                if match('^.*app=.*', line):
                    break

                if match('^.*jp#.*', line):
                    break

                if match('^.*de#.*', line):
                    break

                if match('^.*fr#.*', line):
                    break

                if match('^.*tw#.*', line):
                    break

                if match('^.*hk#.*', line):
                    break

                if match('^.*kr#.*', line):
                    break

                if match('^.*cc#.*', line):
                    break
                if match('^.*@@.*', line):
                    break
                # ||example.org^: block access to the example.org domain and all its subdomains, like www.example.org.
                if match('^\|\|.*\^$', line):
                    domain = line[2:-1]
                    if domain.find('/') >= 0:
                        filter = line
                        break
                    if domain.find('*') >= 0:
                        if domain.startswith('*.') and domain[2:].find('*')<0:
                            domain = domain[2:]
                            block = self.__analysis(domain)
                            break
                        else:
                            filter = line
                            break
                    block = self.__analysis(domain)
                    break
                # @@||example.org^: unblock access to the example.org domain and all its subdomains.
                if match('^@@\|\|.*\^$', line):
                    domain = line[4:-1]
                    if domain.find('*') >= 0 or domain.find('/') >= 0:
                        filter = line
                        break
                    unblock = self.__analysis(domain)
                    break
                # /REGEX/: block access to the domains matching the specified regular expression
                if match('^/.*/$', line):
                    filter = line
                    break
                # 判断是否为单纯的域名
                if line.find('.')>0 and not line.startswith('*.') and not line.startswith('-') and line.find('=')<0 and line.find(':')<0 and line.find('*')<0 and line.find('_')<0 and line.find('?')<0 and line.find(';')<0 and line.find('|')<0 and line.find('$')<0 and line.find('#')<0 and line.find('/')<0:
                    if line[len(line) - 1] == '^':
                        domain = line[:-1]
                    else:
                        domain = line
                    block = self.__analysis(domain)
                    break
                # other
                filter = line
                break
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            return block,unblock,filter

    def resolveHost(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Set[str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterSet:Set[str] = set()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterSet

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block = self.__resolveHost(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterSet)))
        return blockDict,unblockDict,filterSet
    
    def resolveDNS(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Set[str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterSet:Set[str] = set()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterSet

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block,unblock,filter = self.__resolveDNS(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
                if unblock:
                    if unblock[0] not in unblockDict:
                        unblockDict[unblock[0]] = {unblock[1],}
                    else:
                        unblockDict[unblock[0]].add(unblock[1])
                if filter:
                    filterSet.add(filter)
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterSet)))
        return blockDict,unblockDict,filterSet
    
    def resolveFilter(self, rule:Rule) -> Tuple[Dict[str,Set[str]],Dict[str,Set[str]],Set[str]]:
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterSet:Set[str] = set()

        filename = self.path + '/' + rule.filename

        if not os.path.exists(filename):
            return blockDict,unblockDict,filterSet

        with open(filename, "r") as f:
            for line in f:
                # 去掉换行符
                line = line.replace('\r', '').replace('\n', '').strip()
                # 去掉空行
                if len(line) < 1:
                    continue

                block,unblock,filter = self.__resolveFilter(line)
                
                if block:
                    if block[0] not in blockDict:
                        blockDict[block[0]] = {block[1],}
                    else:
                        blockDict[block[0]].add(block[1])
                if unblock:
                    if unblock[0] not in unblockDict:
                        unblockDict[unblock[0]] = {unblock[1],}
                    else:
                        unblockDict[unblock[0]].add(unblock[1])
                if filter:
                    filterSet.add(filter)
        logger.info("%s: block=%d, unblock=%d, filter=%d"%(rule.name,len(blockDict),len(unblockDict),len(filterSet)))
        return blockDict,unblockDict,filterSet
